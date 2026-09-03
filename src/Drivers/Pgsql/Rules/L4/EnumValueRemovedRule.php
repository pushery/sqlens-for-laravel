<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L4;

use Override;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Findings\Confidence;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\ExpandContractTemplate;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * PostgreSQL enum changes are asymmetric: you can add a value, but you cannot drop one —
 * there is no `ALTER TYPE … DROP VALUE`. This rule catches the two ways a value
 * effectively goes away, both of which break a running old application version that
 * still writes or compares the value:
 *
 *  - `ALTER TYPE … RENAME VALUE` — the old value is gone the moment it renames.
 *  - The REBUILD pattern — a new enum type, an `ALTER COLUMN … TYPE … USING`, and a
 *    `DROP TYPE` of the old one — which is how you remove a value when there is no
 *    direct statement for it. Recognized here by its shape: the migration drops a type
 *    it did not create while also building a new enum type.
 *
 * It is HEURISTIC on purpose, and this is exactly the honesty boundary the confidence
 * axis exists for: the tool sees the SQL, not the application code, so whether the
 * change actually breaks anything depends on whether some running version still uses
 * the value — which cannot be proven from the migration. The finding names the safe
 * sequence (add first, deploy the code, clean up in a later deploy) as guidance, not
 * as a verdict on the app.
 *
 * The exception: renaming a value in a type this same migration created is fine — the
 * type does not exist for any old app version yet. Detection is on the canonical form.
 */
final class EnumValueRemovedRule extends AbstractPgsqlSafetyRule implements ProvidesRemediation
{
    /** The staged swap this rule points at — the NEUTRAL sequence, not a PostgreSQL copy of it. */
    private readonly ExpandContractTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new ExpandContractTemplate;
    }

    public function id(): string
    {
        return 'PG.L4.ENUM_VALUE_REMOVED';
    }

    /**
     * The staged column swap — because there is no statement that removes an enum value.
     *
     * Not "removing is expensive": `ALTER TYPE … DROP VALUE` does not exist. So the remedy is a new
     * type and a column moved onto it, which is expand/contract and already has a template. Handing
     * over THAT one rather than writing an enum-flavored copy is the whole point: two four-phase
     * plans drift the first time either is touched, and both look correct alone.
     *
     * The plan's placeholders stay standing here, and that is honest rather than lazy. Neither the
     * new type's name nor its member list is in a statement that RENAMES a value or drops a type —
     * they are decisions, and this template has never invented one.
     *
     * It answers nothing at all for a statement outside those two shapes. That the collector only
     * ever asks about a statement this rule flagged is true and is not enough: it is not the only
     * caller — the agent layer holds the seam directly — and a precondition nobody states is one
     * every later caller has to rediscover. So the shape is read here too, from {@see
     * removalShape()}, which is the same reading {@see judge()} makes rather than a second one.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        return $this->removalShape($statement) === null
            ? null
            : $this->template->payload([], $this->id(), $this->downtimeClass());
    }

    public function level(): Level
    {
        return Level::BackwardCompatibility;
    }

    /** Online: catalog changes, no table lock. The risk is compatibility — the level. */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    /**
     * Heuristic: the compatibility break depends on whether a running application still
     * uses the value, which the tool cannot see. A reader must read the verdict as a
     * flag to check, not a proof.
     */
    #[Override]
    public function confidence(): Confidence
    {
        return Confidence::Heuristic;
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        return match ($this->removalShape($statement)) {
            'rename' => 'ALTER TYPE … RENAME VALUE removes the old value: any running application version '
                .'that still writes or compares it breaks, and PostgreSQL cannot rename it back cleanly. '
                .'The compatible sequence is to add the new value first, deploy the code that uses it, '
                .'and only rename or clean up in a later deploy.',
            'rebuild' => 'This migration drops a type while building a new enum type — the shape of removing '
                .'an enum value by rebuilding the type. If so, any running application version that still '
                .'uses a removed value breaks. Add first, deploy the code, and clean up in a later deploy; '
                .'SQLens reads only the SQL, so treat this as a prompt to check, not a proof.',
            default => null,
        };
    }

    /**
     * Which of the two removal shapes this statement is, if either — read ONCE, for both consumers.
     *
     * The verdict and the fix material must never disagree about what they are looking at, and two
     * copies of these patterns would be exactly how they came to. The type-name capture is the
     * reason the two branches cannot simply be booleans: each shape is excused by a DIFFERENT
     * question about the same name — a rename of a type born here breaks no old version, and a drop
     * of a type born here is the migration cleaning up after itself.
     *
     * @return 'rename'|'rebuild'|null
     */
    private function removalShape(MigrationStatementView $statement): ?string
    {
        $canonical = $statement->canonical;

        if (preg_match('/\bALTER TYPE\s+"?([a-z_][a-z0-9_.]*)"?\s+RENAME\s+VALUE\b/i', $canonical, $matches) === 1) {
            // Renaming a value in a type born in this migration breaks nothing — no old
            // app version knows the type yet.
            return $statement->migration->createsEnumType($matches[1]) ? null : 'rename';
        }

        // The rebuild pattern: a DROP TYPE of a type not created here, in a migration that
        // is also building a new enum type — the shape of "remove a value by rebuilding".
        if (
            preg_match('/\bDROP TYPE\s+(?:IF EXISTS\s+)?"?([a-z_][a-z0-9_.]*)"?/i', $canonical, $matches) === 1
            && ! $statement->migration->createsEnumType($matches[1])
            && $statement->migration->buildsAnEnumType()
        ) {
            return 'rebuild';
        }

        return null;
    }
}
