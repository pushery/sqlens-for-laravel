<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\StatisticsContext;
use Pushery\SQLens\Severity\Severity;

/**
 * The same finding, weighed against how big the thing it names actually is.
 *
 * A COPY-forcing ALTER on an empty table is noise. On four hundred million rows it is an incident
 * announced in advance. Both are the same finding with the same id — what differs is what it costs,
 * and that is a fact about the database rather than about the migration.
 *
 * ## Only up, never down — and never a new finding
 *
 * Statistics may RAISE a severity. They may not lower one and they may not create or remove a
 * finding. All three of those follow from one property: a row estimate depends on when somebody last
 * ran ANALYZE. A number that could silence a finding would make the report depend on that, and the
 * same migration would pass on Monday and fail on Friday with nothing having changed but a
 * statistics refresh.
 *
 * Raising is safe in a way lowering is not. The worst a stale estimate can do here is fail to raise
 * something — leaving the original verdict, which was already the honest one.
 *
 * ## Why the escalation never becomes a rule
 *
 * The finding id is untouched, always. That is what keeps the promise that a predeploy run reports a
 * SUBSET of what lint reports: everything the gate says, CI could have said, only quieter. A new id
 * here would be a rule that only exists when a database is reachable — undeterminable in CI and
 * unreproducible anywhere else.
 */
final readonly class SeverityEscalator
{
    public function __construct(private EscalationThresholds $thresholds) {}

    /**
     * A finding weighed against its object's statistics.
     *
     * Returns the finding UNCHANGED when nothing earns a raise, which is the common case and the
     * one that must stay cheap: a run against a small schema should not rebuild every finding it
     * touches.
     */
    public function escalate(Finding $finding, string $operation, ?StatisticsContext $statistics): Finding
    {
        if (! $statistics instanceof StatisticsContext) {
            // No statistics is not "small". The finding stands exactly as lint produced it, and the
            // reason there is no note here is that the finding already carries its own context
            // channel — one absence reported twice reads as two problems.
            return $finding;
        }

        $step = $this->thresholds->stepFor(
            $operation,
            $statistics->rows?->value,
            $statistics->bytes?->value,
        );

        if ($step === null) {
            return $finding;
        }

        $earned = $step['raise_to'];
        $current = $finding->severity;

        // Strictly greater, so a threshold can never quiet a finding somebody else already rated
        // higher — a security rule that called something critical does not become high because a
        // table turned out to be medium-sized.
        if ($current instanceof Severity && $this->rank($current) >= $this->rank($earned)) {
            return $finding;
        }

        return $finding
            ->withStatistics($statistics)
            ->withSeverity($earned)
            ->withEscalation(new Escalation(
                // `Info` when the rule stated no severity at all. That is the honest base: the
                // finding was reported and rated nothing, so a raise from it is still a raise, and
                // recording the absence as `null` would leave a consumer computing the delta from a
                // value that is not on the axis.
                baseSeverity: $current ?? Severity::Info,
                escalatedSeverity: $earned,
                operation: $operation,
                // From which comparison MATCHED, not from which key is present. A step declaring
                // both — no shipped one does; a project override may — would otherwise report a
                // threshold the object never crossed, which is a wrong number in the line somebody
                // reads before deciding whether to deploy.
                threshold: $step['matched_threshold'],
                unit: $step['matched_on'],
            ));
    }

    /**
     * Where a severity sits, as a number.
     *
     * Declared here rather than taken from the enum's order, because an enum's case order is a
     * fact about a file and this is a fact about meaning. A case reordered for tidiness would
     * silently change which findings escalate.
     */
    private function rank(Severity $severity): int
    {
        return match ($severity) {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        };
    }
}
