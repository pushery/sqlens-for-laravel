<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Squawk;

use Pushery\SQLens\Findings\Finding;

/**
 * Merges the tool's findings into a run's own, so one problem is reported once.
 *
 * The rule is one-directional and it is the whole design: a SQLens finding is NEVER dropped or
 * changed by anything the tool said. The set of own findings a run produces has to be identical
 * with the tool installed and without it — otherwise a laptop and a CI container would gate
 * differently on the same migration, which is the one difference nobody can reconstruct from a
 * report afterwards.
 *
 * What the tool adds is therefore exactly two things: a confirmation stamped on a finding that
 * already existed, and the findings SQLens has no rule for. Everything else it said about ground
 * we already cover is dropped — not because it is wrong, but because a reader handed the same
 * advice twice starts skimming, and the next thing they skim is the finding they had not seen.
 */
final readonly class SquawkDeduplicator
{
    public function __construct(
        private SquawkRuleMap $map,
        /** The version stamped onto a confirmation, so a report says WHICH build agreed. */
        private string $toolVersion,
    ) {}

    /**
     * @param  list<Finding>  $own  the findings SQLens produced itself
     * @param  list<Finding>  $tool  the mapped findings the tool produced
     * @return SquawkDeduplication the same own findings, some of them confirmed, plus what only
     *                             the tool found
     */
    public function merge(array $own, array $tool): SquawkDeduplication
    {
        $confirmed = [];
        $additional = [];

        foreach ($tool as $finding) {
            $key = $this->keyForTool($finding);
            $match = $key === null ? null : $this->firstMatch($own, $key);

            if ($match === null) {
                // Nothing of ours covers this. It stands on its own, which is the entire point of
                // running an amplifier at all.
                $additional[] = $finding;

                continue;
            }

            $confirmed[$match] = true;
        }

        $merged = [];

        foreach ($own as $index => $finding) {
            $merged[] = isset($confirmed[$index]) ? $finding->confirmedBy('squawk@'.$this->toolVersion) : $finding;
        }

        return new SquawkDeduplication($merged, $additional);
    }

    /**
     * The index of the first own finding that covers the same ground at the same place.
     *
     * FIRST, by the order the run produced them, and that order is already deterministic — so
     * two runs over the same migration confirm the same finding. Where several own findings share
     * a group and a position, the tie is broken by rule id, which is stable and readable in a
     * diff; picking "whichever came back first" would be stable only by accident.
     *
     * @param  list<Finding>  $own
     */
    private function firstMatch(array $own, string $key): ?int
    {
        $candidates = [];

        foreach ($own as $index => $finding) {
            if ($this->keyForOwn($finding) === $key) {
                $candidates[$finding->ruleId] = $index;
            }
        }

        if ($candidates === []) {
            return null;
        }

        ksort($candidates);

        return array_values($candidates)[0];
    }

    /** A tool finding's key: the group its rule belongs to, plus where it is. Null when neither exists. */
    private function keyForTool(Finding $finding): ?string
    {
        $rule = str_starts_with($finding->ruleId, SquawkFindingMapper::ID_PREFIX)
            ? substr($finding->ruleId, strlen(SquawkFindingMapper::ID_PREFIX))
            : $finding->ruleId;

        $group = $this->map->for($rule)?->dedupeGroup;

        return $group === null ? null : $this->key($group, $finding);
    }

    /**
     * An own finding's key: the group the map says its rule belongs to, plus where it is.
     *
     * Read from the same map, in the other direction. A second table of "which of our rules
     * corresponds to which group" would be a second thing to keep in step, and the two would
     * disagree the first time somebody edited one of them.
     */
    private function keyForOwn(Finding $finding): ?string
    {
        foreach ($this->map->rules() as $rule) {
            $mapping = $this->map->for($rule);

            if ($mapping?->sqlensRule === $finding->ruleId && $mapping->dedupeGroup !== null) {
                return $this->key($mapping->dedupeGroup, $finding);
            }
        }

        return null;
    }

    /**
     * Group AND position, never the group alone.
     *
     * Two `DROP TABLE`s in one migration are two problems, and merging them because they share a
     * rule would silence the second one — which is a finding disappearing, the failure this whole
     * class is otherwise built to prevent.
     */
    private function key(string $group, Finding $finding): string
    {
        return implode('|', [
            $group,
            $finding->location->file ?? '',
            (string) ($finding->location->statementIndex ?? -1),
        ]);
    }
}
