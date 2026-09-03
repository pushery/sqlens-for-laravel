<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Agent;

use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Severity\GateAxis;
use Pushery\SQLens\Severity\GateDecision;
use Pushery\SQLens\Severity\Severity;

/**
 * The ORDER of a fix report, modeled and tested rather than inherited from whatever order the
 * findings were collected in.
 *
 * An agent works top to bottom and stops when it runs out of budget or attention. So the order is
 * the format's actual product: a correct list in an arbitrary sequence is a list whose tail nobody
 * reads, and the tail is where an accidental ordering puts the expensive item.
 *
 * ## The order, and why each step is where it is
 *
 * 1. **Blocking before merely reported.** What stops a deploy is what has to be done first. Read
 *    from {@see GateDecision} — the same object the exit code reads, not a second judgment.
 * 2. **Security severity, descending.** A critical is a critical whatever the project's level says.
 * 3. **Downtime class**, `rewrite` → `blocking` → `online`. This is the field that decides what
 *    somebody WRITES next, and a table rewrite is a different afternoon from an online index build.
 * 4. **Level, ascending.** The lower level is the more fundamental rule; fixing it first often
 *    removes the higher one.
 * 5. **Rule id, then file, then line** — a byte comparison, so equals never swap between two runs.
 *
 * ## The two axes are ordered, never summed
 *
 * Level and severity each get their own step. They are never combined into a score, and this is
 * not a stylistic preference: a single number cannot say whether an item is high because a project
 * chose to be pedantic or because the risk is real, and those two call for opposite responses.
 * Because they are separate steps, a critical security finding sits at the top of a level-0 run
 * without the level axis disappearing — it still orders everything below it.
 *
 * ## An estimate stays an estimate
 *
 * A severity raised from table statistics arrives already marked, from the engine that raised it.
 * This class ORDERS by it and never re-derives it: a prioritizer that recomputed an escalation
 * would be a second estimator, and the two would disagree about a table nobody re-measured.
 */
final readonly class BriefingPrioritizer
{
    /**
     * The downtime order, worst first. Explicit rather than the enum's declaration order, because
     * an enum's order is an implementation detail and this is a decision.
     *
     * @var array<string, int>
     */
    private const array DOWNTIME_RANK = [
        DowntimeClass::Rewrite->value => 0,
        DowntimeClass::Blocking->value => 1,
        DowntimeClass::Online->value => 2,
    ];

    /**
     * The decided findings in the order a reader should work them.
     *
     * Takes the pairs the reporter already computed rather than computing gate decisions of its
     * own — one decision, several readers, which is the same arrangement the exit code and the JSON
     * summary sit in.
     *
     * @param  list<array{0: Finding, 1: GateDecision}>  $decided
     * @return list<array{0: Finding, 1: GateDecision}>
     */
    public function order(array $decided): array
    {
        usort($decided, $this->compare(...));

        return $decided;
    }

    /**
     * A second VIEW, grouped by the file somebody has to open.
     *
     * It mirrors the priority order rather than replacing it: groups appear in the order of their
     * highest-priority finding, and inside a group the same order holds. Somebody working file by
     * file gets the same sequence, folded — never a different set of priorities wearing a different
     * heading.
     *
     * @param  list<array{0: Finding, 1: GateDecision}>  $decided
     * @return array<string, list<array{0: Finding, 1: GateDecision}>>
     */
    public function byLocation(array $decided): array
    {
        $grouped = [];

        foreach ($this->order($decided) as $pair) {
            // First appearance wins the group's position, and `order()` already put the highest
            // priority first — so the groups come out in priority order without a second sort.
            $grouped[$pair[0]->location->file ?? $pair[0]->location->objectName ?? 'the run'][] = $pair;
        }

        return $grouped;
    }

    /**
     * @param  array{0: Finding, 1: GateDecision}  $a
     * @param  array{0: Finding, 1: GateDecision}  $b
     */
    private function compare(array $a, array $b): int
    {
        return $this->blocking($a[1]) <=> $this->blocking($b[1])
            ?: $this->severityRank($a[0]) <=> $this->severityRank($b[0])
            ?: $this->downtimeRank($a[0]) <=> $this->downtimeRank($b[0])
            ?: $a[0]->level->value <=> $b[0]->level->value
            ?: strcmp($a[0]->ruleId, $b[0]->ruleId)
            ?: strcmp($a[0]->location->file ?? '', $b[0]->location->file ?? '')
            ?: ($a[0]->location->line ?? 0) <=> ($b[0]->location->line ?? 0);
    }

    /** 0 for a finding that stops a deploy, 1 for one that does not — blocking sorts first. */
    private function blocking(GateDecision $decision): int
    {
        return $decision->blockedBy instanceof GateAxis ? 0 : 1;
    }

    /**
     * Severity as a sort key, worst first — and an UNRATED finding sorts after every rated one.
     *
     * Not "treated as lowest risk": a finding with no severity was never measured on that axis at
     * all, and putting it above a rated `low` would be claiming a comparison nobody made. Below
     * them is where the level axis, the next step, gets to order it.
     */
    private function severityRank(Finding $finding): int
    {
        return $finding->severity instanceof Severity ? -$finding->severity->rank() : PHP_INT_MAX;
    }

    /** The downtime class as a sort key; a finding without one sorts after every finding with one. */
    private function downtimeRank(Finding $finding): int
    {
        $class = $finding->downtimeClass;

        return $class instanceof DowntimeClass ? self::DOWNTIME_RANK[$class->value] : PHP_INT_MAX;
    }
}
