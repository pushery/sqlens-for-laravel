<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Pgls;

use Pushery\SQLens\Findings\Finding;

/**
 * Merges the tool's findings into a run's own, so one problem is reported once.
 *
 * ## The rule is one-directional, and that is the whole design
 *
 * A SQLens finding is NEVER dropped or changed by anything the tool said. The set of own findings
 * a run produces is identical with the binary installed and without it — otherwise a laptop and a
 * CI container would gate differently on the same database, which is the one difference nobody can
 * reconstruct from a report afterwards.
 *
 * What the tool adds is exactly two things: a confirmation stamped on a finding that already
 * existed, and the findings this package has no rule for. Everything else it said about ground we
 * already cover is dropped — not because it is wrong, but because a reader handed the same advice
 * twice starts skimming, and the next thing they skim is the finding they had not seen.
 *
 * ## Matching is by rule AND object, never by rule alone
 *
 * A `dblint` diagnostic names a schema object, not a file position, so that object is what makes
 * two findings the same finding. Matching on the rule pair alone would collapse every table with
 * row-level security disabled into one — the run would report the first and silently drop the rest,
 * which is a worse failure than a duplicate: a duplicate is noise, a dropped table is a hole.
 */
final readonly class PglsDeduplicator
{
    public function __construct(
        /** Stamped onto a confirmation, so a report says WHICH build agreed. */
        private string $toolVersion,
    ) {}

    /**
     * @param  list<Finding>  $own  the findings SQLens produced itself
     * @param  list<Finding>  $tool  the mapped findings the tool produced
     */
    public function merge(array $own, array $tool): PglsDeduplication
    {
        $additional = [];
        $confirmed = [];

        foreach ($tool as $finding) {
            $key = $this->keyForTool($finding);
            $match = $key === null ? null : $this->firstMatch($own, $key);

            if ($match === null) {
                $additional[] = $finding;

                continue;
            }

            $confirmed[$match] = true;
        }

        $merged = [];

        foreach ($own as $index => $finding) {
            $merged[] = isset($confirmed[$index]) ? $finding->confirmedBy('pgls@'.$this->toolVersion) : $finding;
        }

        return new PglsDeduplication($merged, $additional);
    }

    /**
     * The index of the first own finding that covers the same ground on the same object.
     *
     * FIRST by the order the run produced them, which is already deterministic — so two runs over
     * the same database confirm the same finding. A tie between several own findings on one object
     * is broken by rule id, which is stable and readable in a diff; taking "whichever came back
     * first" would be stable only by accident.
     *
     * @param  list<Finding>  $own
     */
    private function firstMatch(array $own, string $key): ?int
    {
        $candidates = [];

        foreach ($own as $index => $finding) {
            if ($this->keyForOwn($finding) === $key) {
                // `??=`, not `=`. Two own findings can share a rule AND an object — the same rule
                // firing twice on one table is unusual but not impossible — and plain assignment
                // would keep the LAST index while the note above promises the first. A docblock
                // that says "first" over code that takes the last is worse than either behavior:
                // it is the one a reader will not check.
                $candidates[$finding->ruleId] ??= $index;
            }
        }

        if ($candidates === []) {
            return null;
        }

        ksort($candidates);

        return array_values($candidates)[0];
    }

    /**
     * A tool finding's key: the SQLens rule its own rule maps onto, plus the object it is about.
     *
     * Null when the rule has no counterpart here — which is the ordinary case for four of the six,
     * and the reason those pass straight through as additions.
     */
    private function keyForTool(Finding $finding): ?string
    {
        $rule = str_starts_with($finding->ruleId, PglsFindingMapper::ID_PREFIX)
            ? substr($finding->ruleId, strlen(PglsFindingMapper::ID_PREFIX))
            : null;

        $sqlensRule = $rule === null ? null : PglsDeduplicationMap::sqlensRuleFor($rule);

        return $sqlensRule === null ? null : $this->key($sqlensRule, $finding);
    }

    /** An own finding's key, in the same shape, so the two are comparable at all. */
    private function keyForOwn(Finding $finding): ?string
    {
        return $this->key($finding->ruleId, $finding);
    }

    /**
     * Rule and object, joined.
     *
     * Null when the finding names no object: a finding about the database as a whole cannot be
     * matched against one about a table, and treating "no object" as an object would make every
     * unplaced finding a duplicate of every other one.
     */
    private function key(string $sqlensRule, Finding $finding): ?string
    {
        $object = $finding->location->objectName;

        return $object === null || $object === '' ? null : $sqlensRule.'@'.$object;
    }
}
