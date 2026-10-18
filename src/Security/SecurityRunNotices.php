<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security;

use Pushery\SQLens\Catalog\Security\SecurityNotice;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Findings\CredentialRedactor;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * The findings a security run makes about ITSELF.
 *
 * A sub-run that could not happen is the one thing an aggregate must not express by being shorter.
 * Two halves that each return nothing look identical to one half that returned nothing and one that
 * never ran — and the second is the report that reads as a clean database while half of it was never
 * examined.
 *
 * Built here rather than inside the runner so the runner holds orchestration and nothing else, and
 * so the sentence a reader gets is written once for both halves instead of twice with a drift
 * between them.
 */
final readonly class SecurityRunNotices
{
    /** The prefix these report under — the run, not a rule. */
    public const string PREFIX = 'sqlens.security';

    /**
     * One half failed with a message of its own — a crash, a baseline it could not read, or a
     * connection nothing defines.
     *
     * None of them is an ordinary state, so the notice keeps the failure's own message: a
     * paraphrase would lose exactly the part a reader needs, such as the connection names that ARE
     * configured.
     *
     * The detail is redacted here rather than at the caller. Producers write
     * `Throwable::getMessage()` into this field, and `QueryException::formatMessage()` appends
     * ` (Connection: …, Host: …, Port: …, Database: …, SQL: …)` to every query exception on both
     * engines, so a refused catalog read on a managed instance — the ordinary case — would otherwise
     * arrive wearing the connection's coordinates.
     *
     * At the sink, because a new producer inherits the redaction without knowing it exists.
     * Not at {@see Finding}, which would be a filter rather than a sink: the shape redactor removes
     * `role "…"`, `user "…"` and `database "…"`, and that is precisely what a security finding
     * about a role or a database is made of. This field carries error text and nothing else.
     *
     * The reason is the failure's own where it has one, such as `connection_not_configured` for a
     * connection nothing defines, and `sub_run_failed` otherwise.
     */
    public static function subRunCrashed(string $half, string $detail, UndeterminedReason $reason = UndeterminedReason::SubRunFailed): Finding
    {
        return self::halfDidNotRun($half, sprintf('it failed with: %s', new CredentialRedactor()->redact($detail)), $reason);
    }

    /**
     * One half met a connection this package cannot examine.
     *
     * Not an error and not a clean result. SQLite is the ordinary case — a test suite, a local
     * scratch database — and a run that returned nothing there would report an unexamined connection
     * as an examined one.
     *
     * The resolver's own sentence and reason travel with it. A driver this package does not support,
     * a connection without a driver key and a server below the supported floor are different
     * things to fix, so each keeps the sentence and the reason that name it. The runner reads both
     * off the resolver's failure, so the notices need nothing from the driver layer.
     */
    public static function subRunUnsupported(string $half, string $connection, string $detail, UndeterminedReason $reason): Finding
    {
        return self::halfDidNotRun($half, sprintf(
            'the connection "%s" is not one this package can examine: %s',
            $connection,
            $detail,
        ), $reason);
    }

    /**
     * One half refused before it looked: an ambiguous connection, a scope admitting no rule, a
     * config this package cannot read.
     *
     * Its own findings travel along rather than being summarized, because they already say WHICH
     * refusal it was — and a summary here would be a second, worse spelling of a sentence that
     * exists.
     *
     * The reason is the one the first refusal carries, and `sub_run_failed` where none carries one.
     *
     * @param  list<Finding>  $refusals
     */
    public static function subRunRefused(string $half, array $refusals): Finding
    {
        $reasons = array_map(static fn (Finding $finding): string => $finding->ruleId, $refusals);
        $reason = UndeterminedReason::SubRunFailed;

        foreach ($refusals as $refusal) {
            if ($refusal->status->reason instanceof UndeterminedReason) {
                $reason = $refusal->status->reason;

                break;
            }
        }

        return self::halfDidNotRun($half, $reasons === []
            ? 'it stopped on a misconfiguration before reading anything'
            : sprintf('it stopped before reading anything (%s)', implode(', ', array_unique($reasons))), $reason);
    }

    /**
     * A half that was never configured to run — not a failure, and not a pass either.
     *
     * Its own factory beside the three above because the CAUSE is different in kind: those three are
     * a half that tried and could not, this one is a half nobody asked for. A reader acts differently
     * on each — one is a thing to fix, the other a thing to decide — and folding them together would
     * make the report say "could not" about a setting somebody chose.
     */
    public static function subRunNotConfigured(string $half, string $because): Finding
    {
        return self::halfDidNotRun($half, $because, UndeterminedReason::NotConfigured);
    }

    /**
     * A half that reads a result somebody else produced, and read nothing.
     *
     * The reading knows which of the two kinds above it is: `not_configured` where nothing set the
     * half up to read a result, `sub_run_failed` where it could not read the one it was pointed at.
     */
    public static function subRunReadNothing(string $half, string $because, UndeterminedReason $reason): Finding
    {
        return self::halfDidNotRun($half, $because, $reason);
    }

    /**
     * The shared sentence, written once for every factory, with the reason each one knows.
     *
     * `undetermined` rather than a failure: the OTHER half may have found plenty, and turning an
     * unreachable sub-run into a failing run is a decision this layer does not get to make —
     * `strict_undetermined` is where a project makes it.
     */
    private static function halfDidNotRun(string $half, string $because, UndeterminedReason $reason): Finding
    {
        return Finding::undetermined(
            SecurityNotice::NothingChecked->id(),
            self::PREFIX,
            sprintf(
                'The %s half of the security run examined nothing, because %s. This is not a clean '
                .'result for that half: any findings in this report come from the halves that did run.',
                $half,
                $because,
            ),
            $reason,
            Location::inCatalog('unknown', $half, $half, SchemaObjectType::Database),
            Category::Security,
            Level::Capturable,
            StabilityTier::Stable,
            RuleDocumentationUrl::for(SecurityNotice::NothingChecked->id()),
            new SubjectContext(driver: 'unknown', profile: 'local', strictTools: false),
        );
    }
}
