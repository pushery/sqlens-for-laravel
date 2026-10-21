<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Squawk;

use Pushery\SQLens\Findings\Finding;

/**
 * Merges the tool's findings into a run's own, so one problem is reported once.
 *
 * The rule is one-directional and it is the whole design: a SQLens finding is never dropped or
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
        /** The version stamped onto a confirmation, so a report says which build agreed. */
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
        $covered = $this->coveredBy($own);
        $confirmed = [];
        $additional = [];

        foreach ($tool as $finding) {
            $key = $this->keyForTool($finding);
            $match = $key === null ? null : ($covered[$key] ?? null);

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
     * For each key an own finding carries, the index of the own finding that a tool finding on it
     * confirms.
     *
     * Built once per merge, so a merge costs the findings on both sides rather than their product.
     * First, by the order the run produced them, and that order is already deterministic — so
     * two runs over the same migration confirm the same finding. Where several own findings share
     * a group and a position, the tie is broken by rule id, which is stable and readable in a
     * diff; picking "whichever came back first" would be stable only by accident. One rule that
     * fires twice at one position keeps its first finding.
     *
     * @param  list<Finding>  $own
     * @return array<string, int>
     */
    private function coveredBy(array $own): array
    {
        $groups = $this->ownGroups();
        $candidates = [];

        foreach ($own as $index => $finding) {
            $group = $groups[$finding->ruleId] ?? null;

            if ($group !== null) {
                $candidates[$this->key($group, $finding)][$finding->ruleId] ??= $index;
            }
        }

        $covered = [];

        foreach ($candidates as $key => $byRule) {
            ksort($byRule);
            $covered[$key] = array_values($byRule)[0];
        }

        return $covered;
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
     * The group each of our rules belongs to: what an own finding's key is made of, with where it is.
     *
     * Read from the same map, in the other direction. A second table of "which of our rules
     * corresponds to which group" would be a second thing to keep in step, and the two would
     * disagree the first time somebody edited one of them. Where the map names one of our rules
     * under several entries, the first entry with a group decides.
     *
     * @return array<string, string>
     */
    private function ownGroups(): array
    {
        $groups = [];

        foreach ($this->map->rules() as $rule) {
            $mapping = $this->map->for($rule);

            if ($mapping?->sqlensRule !== null && $mapping->dedupeGroup !== null) {
                $groups[$mapping->sqlensRule] ??= $mapping->dedupeGroup;
            }
        }

        return $groups;
    }

    /**
     * Group and position, never the group alone.
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
