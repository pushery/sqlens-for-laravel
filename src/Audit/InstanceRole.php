<?php

declare(strict_types=1);

namespace Pushery\SQLens\Audit;

use Pushery\SQLens\Catalog\InstanceIdentity;
use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * Whether the audited instance accepts writes — and therefore what its answers are worth.
 *
 * ## Why the role changes the meaning of a finding rather than decorating it
 *
 * The same settings finding says two different things depending on where it was read. A
 * `max_connections` that is too low on the primary is a production problem; the same number on a
 * replica describes a machine that serves no writes, and may be deliberately sized differently.
 * Worse, some statements are simply not answerable on a replica — a rule whose subject is the
 * cluster's write path has nothing to measure there. Without the role in the report, a reader has
 * no way to tell which of those they are looking at, and the honest reading of an ambiguous
 * finding is the pessimistic one, which is how a correct configuration gets "fixed".
 *
 * ## Three values, and the third is not a formality
 *
 * The indication comes from one cheap fact — PostgreSQL's `pg_is_in_recovery()`, MySQL's
 * `read_only`/`super_read_only` — and a managed database or a narrow grant can withhold it. When
 * it is withheld the answer is {@see Undetermined}, never {@see Primary}. That direction is
 * deliberate and it is the only safe one: reading silence as "this is the primary" would let every
 * instance-scoped rule report a confident verdict about a machine nobody established the role of,
 * which is precisely the silent green this package exists to refuse.
 *
 * ## What it deliberately does not know
 *
 * It says nothing about replication HEALTH: not the lag, not whether a receiver is connected, not
 * who the primary is. Those live on replication state and activity views, and this class does not
 * read them — not even to sharpen an undetermined into a verdict. Two reasons, and the second is
 * the load-bearing one. The obvious one is scope: lag is a deploy-gate question, and the deploy
 * suite owns it. The one that matters here is that READING those views is itself the boundary
 * crossing — they are the activity reader's territory, and a second reader quietly querying them
 * would both duplicate that work and make this class's promise ("one cheap fact, no state
 * inspection") untrue while every test still passed.
 */
enum InstanceRole: string
{
    /** The instance accepts writes. */
    case Primary = 'primary';

    /** The instance refuses them — in recovery, or sealed read-only. */
    case Replica = 'replica';

    /** Nobody established which, and this is said rather than assumed. */
    case Undetermined = 'undetermined';

    /**
     * The role implied by what the server said about itself.
     *
     * Named `of()` rather than the obvious `from()`: a backed enum already declares `from()` as
     * its value constructor, and redeclaring it is a fatal error at load time — which surfaces as
     * a test run that dies with no output rather than as a failing assertion.
     *
     * Read off `readOnly` alone. A primary somebody has sealed with `read_only=ON` comes back as
     * {@see Replica}, and that is the right answer for this axis rather than a defect: the
     * question the role answers is "can this instance accept writes", and a sealed primary cannot.
     * A rule that needs the finer distinction is asking about replication topology, which is a
     * different question on different views.
     */
    public static function of(?InstanceIdentity $identity): self
    {
        if (! $identity instanceof InstanceIdentity) {
            return self::Undetermined;
        }

        return match ($identity->readOnly) {
            true => self::Replica,
            false => self::Primary,
            null => self::Undetermined,
        };
    }

    /**
     * Why the role could not be established, or null when it was.
     *
     * The reason is the one the reader recorded against `read_only` — a missing privilege, a
     * managed-database restriction, an unreachable server. Passing it through rather than
     * inventing a role-specific reason keeps one explanation for one failure: the report says the
     * grant was missing, not that "the role is unknown", which would leave the operator with
     * nothing to act on.
     */
    public static function undeterminedBecause(?InstanceIdentity $identity): ?UndeterminedReason
    {
        if (self::of($identity) !== self::Undetermined) {
            return null;
        }

        if (! $identity instanceof InstanceIdentity) {
            return UndeterminedReason::ServerUnreachable;
        }

        return $identity->unavailable['read_only'] ?? UndeterminedReason::MissingPrivilege;
    }

    /**
     * Whether a rule whose subject is the write path can be answered here.
     *
     * False for a replica AND for an unestablished role — the two are different situations with
     * the same correct handling, because a verdict nobody can place is worth exactly as much as
     * one placed on the wrong machine.
     */
    public function answersForTheWritePath(): bool
    {
        return $this === self::Primary;
    }
}
