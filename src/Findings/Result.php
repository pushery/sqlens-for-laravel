<?php

declare(strict_types=1);

namespace Pushery\SQLens\Findings;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Reporting\Baseline\BaselineEntry;
use Pushery\SQLens\Reporting\Suppression\ConfigIgnoreRule;
use Pushery\SQLens\Reporting\Suppression\SuppressedFinding;
use Pushery\SQLens\Reporting\Suppression\SuppressionResolver;
use Pushery\SQLens\Severity\GateAxis;
use Pushery\SQLens\Severity\Severity;

/**
 * The run result as an immutable aggregate: a deduplicated, deterministically
 * ordered list of findings plus the run metadata. It is the data reporters and
 * the exit-code contract build on — this aggregate does NOT decide
 * the exit code itself.
 *
 * The three-valued summary is the whole point: overallStatus() lets an
 * undetermined run never read as green. A run whose findings are all
 * undetermined is undetermined, not pass.
 */
final readonly class Result
{
    /**
     * @param  list<Finding>  $findings  deduplicated and deterministically ordered
     * @param  list<SuppressedFinding>  $suppressed  hidden from the gate, never from the record
     * @param  list<BaselineEntry>  $staleBaselineEntries  recorded but matched nothing this run
     * @param  list<ConfigIgnoreRule>  $unusedIgnoreRules  configured but matched nothing this run
     */
    private function __construct(
        public array $findings,
        public RunMetadata $metadata,
        public array $suppressed = [],
        public array $staleBaselineEntries = [],
        public array $unusedIgnoreRules = [],
    ) {}

    /**
     * Build the aggregate. Dedupe by (rule id, location) so a rule that ran in
     * two suites contributes a single finding, then order deterministically by
     * the location sort key, breaking ties by rule id — same state ⇒ same order.
     *
     * Suppressed findings are held SEPARATELY, never mixed into the list the
     * gates read: a suppressed finding must not break a build, and must not read
     * as a pass either. It is its own count.
     *
     * @param  iterable<Finding>  $findings
     * @param  list<SuppressedFinding>  $suppressed
     * @param  list<BaselineEntry>  $staleBaselineEntries
     * @param  list<ConfigIgnoreRule>  $unusedIgnoreRules
     */
    public static function of(iterable $findings, RunMetadata $metadata, array $suppressed = [], array $staleBaselineEntries = [], array $unusedIgnoreRules = []): self
    {
        $deduped = [];
        foreach ($findings as $finding) {
            $deduped[$finding->ruleId.'@'.$finding->location->sortKey()] ??= $finding;
        }

        $ordered = array_values($deduped);
        usort(
            $ordered,
            static fn (Finding $a, Finding $b): int => [$a->location->sortKey(), $a->ruleId]
                <=> [$b->location->sortKey(), $b->ruleId],
        );

        return new self($ordered, $metadata, $suppressed, $staleBaselineEntries, $unusedIgnoreRules);
    }

    /**
     * How many recorded suppressions matched nothing this run — stale baseline
     * entries plus unused ignore rules. A rotting suppression list is its own kind
     * of silent green (it stops describing what the project accepts), so the number
     * is surfaced, never left for someone to notice.
     */
    public function staleSuppressionCount(): int
    {
        return count($this->staleBaselineEntries) + count($this->unusedIgnoreRules);
    }

    /**
     * The three-valued run summary. Any fail ⇒ fail; otherwise any undetermined
     * ⇒ undetermined; otherwise pass. Undetermined NEVER collapses to pass — an
     * empty run is the only way to a bare pass.
     */
    public function overallStatus(): Outcome
    {
        $sawUndetermined = false;

        foreach ($this->findings as $finding) {
            if ($finding->status->isFail()) {
                return Outcome::Fail;
            }

            if ($finding->status->isUndetermined()) {
                $sawUndetermined = true;
            }
        }

        return $sawUndetermined ? Outcome::Undetermined : Outcome::Pass;
    }

    /**
     * Count per outcome, every outcome present so the shape is stable.
     *
     * @return array<string, int>
     */
    public function countsByStatus(): array
    {
        $counts = [];
        foreach (Outcome::cases() as $outcome) {
            $counts[$outcome->value] = 0;
        }

        foreach ($this->findings as $finding) {
            $counts[$finding->status->outcome->value]++;
        }

        return $counts;
    }

    /**
     * Count per category, every category present so the shape is stable.
     *
     * @return array<string, int>
     */
    public function countsByCategory(): array
    {
        $counts = [];
        foreach (Category::cases() as $category) {
            $counts[$category->value] = 0;
        }

        foreach ($this->findings as $finding) {
            $counts[$finding->category->value]++;
        }

        return $counts;
    }

    /**
     * Count per level, every level present so the shape is stable.
     *
     * @return array<int, int>
     */
    public function countsByLevel(): array
    {
        $counts = [];
        foreach (Level::cases() as $level) {
            $counts[$level->value] = 0;
        }

        foreach ($this->findings as $finding) {
            $counts[$finding->level->value]++;
        }

        return $counts;
    }

    /**
     * Count per downtime class, every class present so the shape is stable.
     *
     * It exists so a deploy script can ask "does this release block or rewrite
     * anything?" from the report HEAD, without walking every finding and without
     * needing to know which rules carry the field. A finding whose rule declared no
     * class is not counted — absence there means the rule makes no claim about
     * downtime, which is not the same as claiming `online`.
     *
     * @return array<string, int>
     */
    public function countsByDowntimeClass(): array
    {
        $counts = [];
        foreach (DowntimeClass::cases() as $class) {
            $counts[$class->value] = 0;
        }

        foreach ($this->findings as $finding) {
            if ($finding->downtimeClass instanceof DowntimeClass) {
                $counts[$finding->downtimeClass->value]++;
            }
        }

        return $counts;
    }

    /**
     * The most disruptive downtime class any finding in this run carries — or null.
     *
     * ## Why an aggregate beside the histogram
     *
     * `countsByDowntimeClass()` already answers "how many of each", and a deploy script CAN derive
     * this from it. It should not have to: deriving means knowing the ORDER of the three classes,
     * which is this package's judgment rather than the consumer's, and every script that re-derives
     * it is free to get it wrong in its own way. One of them eventually treats `rewrite` as milder
     * than `blocking` — the ranking is not alphabetical and not obvious — and the mistake is silent.
     *
     * ## Why null rather than `online`
     *
     * A run where nothing carries a downtime class has not established that everything is online.
     * Most findings have none at all: the class is a property of a schema OPERATION, and a security
     * or convention finding is not one. Answering `online` would turn "nobody stated a class" into
     * "nothing disrupts", which is the reading this package refuses everywhere else.
     */
    public function worstDowntimeClass(): ?DowntimeClass
    {
        $worst = null;

        foreach ($this->findings as $finding) {
            if (! $finding->downtimeClass instanceof DowntimeClass) {
                continue;
            }

            if (! $worst instanceof DowntimeClass || $finding->downtimeClass->atLeastAsDisruptiveAs($worst)) {
                $worst = $finding->downtimeClass;
            }
        }

        return $worst;
    }

    /**
     * Count per severity, every severity present so the shape is stable. Findings
     * without a severity (the level-gated majority) are not counted here — the
     * severity axis is separate from the level axis.
     *
     * @return array<string, int>
     */
    public function countsBySeverity(): array
    {
        $counts = [];
        foreach (Severity::cases() as $severity) {
            $counts[$severity->value] = 0;
        }

        foreach ($this->findings as $finding) {
            if ($finding->severity instanceof Severity) {
                $counts[$finding->severity->value]++;
            }
        }

        return $counts;
    }

    /**
     * Count per undetermined reason, every reason present so the shape is stable.
     * A pass or fail finding carries no reason and is not counted, so this bundles
     * exactly the "could not conclude" outcomes for the reporter — no silent green,
     * because every undetermined already points at a named reason.
     *
     * @return array<string, int>
     */
    public function countsByUndeterminedReason(): array
    {
        $counts = [];
        foreach (UndeterminedReason::cases() as $reason) {
            $counts[$reason->value] = 0;
        }

        foreach ($this->findings as $finding) {
            if ($finding->status->reason instanceof UndeterminedReason) {
                $key = $finding->status->reason->value;
                $counts[$key] = ($counts[$key] ?? 0) + 1;
            }
        }

        return $counts;
    }

    /**
     * Suppressed findings per GATE AXIS — the number a security review needs and the source count
     * cannot give.
     *
     * Per source answers "who hid it"; per axis answers "what was hidden". Those are different
     * questions and only the second one notices a critical security finding disappearing into a
     * collective total: "12 suppressed by config" reads the same whether the twelve are naming
     * conventions or password literals.
     *
     * Every axis is present even at zero, like every other count map here, so the shape of the
     * summary never varies with the contents of a run.
     *
     * @return array<string, int>
     */
    public function countsBySuppressedAxis(): array
    {
        $counts = [];

        foreach (GateAxis::cases() as $axis) {
            $counts[$axis->value] = 0;
        }

        foreach ($this->suppressed as $hidden) {
            $counts[GateAxis::forCategory($hidden->finding->category)->value]++;
        }

        return $counts;
    }

    /**
     * How many findings each suppression layer hid. Every source is present even
     * at zero, so the balance keeps a stable shape for machine consumers — and a
     * suppression can never be counted without naming who made it.
     *
     * @return array<string, int>
     */
    public function countsBySuppressionSource(): array
    {
        $counts = [];
        foreach (SuppressionResolver::ORDER as $source) {
            $counts[$source] = 0;
        }

        foreach ($this->suppressed as $hidden) {
            $counts[$hidden->suppression->source]++;
        }

        return $counts;
    }

    /**
     * A deterministic array projection with a fixed key order. The findings are
     * already deduplicated and stably ordered, so two projections of the same
     * state serialize byte-identically.
     *
     * @return array{
     *     overall_status: string,
     *     counts: array{status: array<string, int>, category: array<string, int>, level: array<int, int>, severity: array<string, int>, undetermined_reason: array<string, int>, suppressed_by_source: array<string, int>},
     *     metadata: array<string, mixed>,
     *     findings: list<array<string, mixed>>,
     *     suppressed: list<array<string, mixed>>,
     * }
     */
    public function toArray(): array
    {
        return [
            'overall_status' => $this->overallStatus()->value,
            'counts' => [
                'status' => $this->countsByStatus(),
                'category' => $this->countsByCategory(),
                'level' => $this->countsByLevel(),
                'severity' => $this->countsBySeverity(),
                'undetermined_reason' => $this->countsByUndeterminedReason(),
                'suppressed_by_source' => $this->countsBySuppressionSource(),
            ],
            'metadata' => $this->metadata->toArray(),
            'findings' => array_map(static fn (Finding $finding): array => $finding->toArray(), $this->findings),
            'suppressed' => array_map(static fn (SuppressedFinding $hidden): array => $hidden->toArray(), $this->suppressed),
        ];
    }
}
