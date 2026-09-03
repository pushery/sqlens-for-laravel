<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Outcome;

/**
 * The second reading that turns a NAME into a verdict.
 *
 * ## The promise this keeps
 *
 * `DEPLOY.LEGACY.ORPHAN_TRANSITION_OBJECT` and its MySQL twin report an object whose name looks like
 * an unfinished migration left it — `users_old`, `_orders_gho`, `#sql-1234_a` — and both say, in
 * their own words, that a name is not evidence and that what would settle it is the object appearing
 * in **no migration state at all**.
 *
 * That is exactly what an expectation comparison establishes. When `--expect-shadow` has run and the
 * comparison reports the same object as `unexpected_in_database`, the two readings agree from
 * different directions: the name says leftover, and the migrations say nothing describes it. That is
 * no longer a guess, and it is reported as `fail`.
 *
 * ## Why the combining happens here and not inside the checks
 *
 * A check that reached for a drift report would own two subjects under one id, and would answer
 * differently depending on whether an option somebody else passed had run — so its rung would stop
 * being a property of what the check can prove. The check's own docblock draws the line and this
 * class sits on the other side of it: the check owns the catalog reading and the name heuristic,
 * this owns the agreement between two readings, and nothing owns both.
 *
 * ## What it will NOT do
 *
 * It never demotes, and it never promotes on silence. A comparison that did not run, or ran and
 * found the object perfectly expected, leaves the undetermined finding exactly as it was: the name
 * still looks like a leftover, and that observation did not become false because a second reading
 * disagreed. Promotion needs agreement — an absence is not one.
 *
 * Matching is on the FULL qualified name and nothing looser. A bare-name match across schemas would
 * promote `archive.orders_old` on the strength of `public.orders_old` being unexpected, which is a
 * confident, specific statement about the wrong object. When the two namings do not line up, nothing
 * is promoted and the finding keeps its honest rung — the safe direction of a wrong guess.
 */
final readonly class ExpectationEscalation
{
    /**
     * The finding ids this promotion applies to — the two name-based leftover checks and nothing
     * else.
     *
     * Named rather than derived from the undetermined reason, because the reason says WHY an answer
     * is uncertain and this is about WHICH question a second reading can settle. A future check that
     * is undetermined for its own reasons must not be promoted by a comparison that never asked
     * about it.
     *
     * @var list<string>
     */
    public const array PROMOTABLE = [
        'DEPLOY.LEGACY.ORPHAN_TRANSITION_OBJECT',
        'DEPLOY.LEGACY.OSC_ARTIFACT',
    ];

    /**
     * @param  list<Finding>  $findings
     * @return array{findings: list<Finding>, promoted: int}
     */
    public static function apply(array $findings, ExpectationReport $expectation): array
    {
        if (! $expectation->compared || $expectation->unexpectedObjects === []) {
            return ['findings' => $findings, 'promoted' => 0];
        }

        $promoted = 0;
        $settled = [];

        foreach ($findings as $finding) {
            $decided = self::promote($finding, $expectation->unexpectedObjects);
            $promoted += $decided === $finding ? 0 : 1;
            $settled[] = $decided;
        }

        return ['findings' => $settled, 'promoted' => $promoted];
    }

    /** @param list<string> $unexpected */
    private static function promote(Finding $finding, array $unexpected): Finding
    {
        if ($finding->status->outcome !== Outcome::Undetermined) {
            return $finding;
        }

        if (! in_array($finding->ruleId, self::PROMOTABLE, true)) {
            return $finding;
        }

        $object = $finding->location->objectName;

        if (! is_string($object) || $object === '' || ! in_array($object, $unexpected, true)) {
            return $finding;
        }

        // The message is rewritten rather than extended, because the two halves would contradict
        // each other: the undetermined text ends by naming what would settle the question, and a
        // reader seeing `fail` beside it would not know which half to believe. This says the whole
        // thing once.
        return $finding->settledBySecondReading(sprintf(
            'The object `%s` is a leftover, and two independent readings agree on it: its name is '
            .'the one an unfinished expand/contract migration leaves behind, and the shadow replay '
            .'of your migrations produced no such object at all — nothing in your migration history '
            .'describes it. Remove it in a migration of its own. SQLens never drops anything itself, '
            .'so read the DROP as a proposal; a drop cannot be undone, and this run has proved that '
            .'the object is undescribed, not that nothing reads it.',
            $object,
        ));
    }
}
