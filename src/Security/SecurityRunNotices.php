<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security;

use Pushery\SQLens\Catalog\Security\SecurityNotice;
use Pushery\SQLens\Categories\Category;
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
     * One half threw — a genuine crash rather than a refusal.
     *
     * The rarest of the three and the only one that is not an ordinary state, so it keeps the
     * exception's own message: a paraphrase would lose exactly the part a reader needs.
     */
    public static function subRunCrashed(string $half, string $detail): Finding
    {
        return self::halfDidNotRun($half, sprintf('it failed with: %s', $detail));
    }

    /**
     * One half met a driver this package does not support.
     *
     * Not an error and not a clean result. SQLite is the ordinary case — a test suite, a local
     * scratch database — and a run that returned nothing there would report an unexamined connection
     * as an examined one.
     */
    public static function subRunUnsupported(string $half, string $connection): Finding
    {
        return self::halfDidNotRun($half, sprintf(
            'the connection "%s" uses a driver this package does not support, so that half examined nothing',
            $connection,
        ));
    }

    /**
     * One half refused before it looked: an ambiguous connection, a scope admitting no rule, a
     * config this package cannot read.
     *
     * Its own findings travel along rather than being summarized, because they already say WHICH
     * refusal it was — and a summary here would be a second, worse spelling of a sentence that
     * exists.
     *
     * @param  list<Finding>  $refusals
     */
    public static function subRunRefused(string $half, array $refusals): Finding
    {
        $reasons = array_map(static fn (Finding $finding): string => $finding->ruleId, $refusals);

        return self::halfDidNotRun($half, $reasons === []
            ? 'it stopped on a misconfiguration before reading anything'
            : sprintf('it stopped before reading anything (%s)', implode(', ', array_unique($reasons))));
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
        return self::halfDidNotRun($half, $because);
    }

    /**
     * The shared sentence, written once for all three reasons.
     *
     * `undetermined` rather than a failure: the OTHER half may have found plenty, and turning an
     * unreachable sub-run into a failing run is a decision this layer does not get to make —
     * `strict_undetermined` is where a project makes it.
     */
    private static function halfDidNotRun(string $half, string $because): Finding
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
            UndeterminedReason::NotConfigured,
            Location::inCatalog('unknown', $half, $half, SchemaObjectType::Database),
            Category::Security,
            Level::Capturable,
            StabilityTier::Stable,
            RuleDocumentationUrl::for(SecurityNotice::NothingChecked->id()),
            new SubjectContext(driver: 'unknown', profile: 'local', strictTools: false),
        );
    }
}
