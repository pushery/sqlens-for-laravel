<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Summary;

use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Reporting\RunContext;
use Pushery\SQLens\Severity\GateAxis;
use Pushery\SQLens\Severity\GateDecision;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Severity\SeverityGate;

/**
 * Separates the two orthogonal gates so a reader can see WHICH one a run breached —
 * never a single merged number without provenance (that is the pitfall this exists
 * to close). The level gate counts the ordinary fails within the run's strictness
 * level; the severity gate counts the security/privacy fails at or above the
 * configured floor. A finding is measured against exactly one gate, decided by its
 * category, so the two counts never double-count.
 *
 * The gates are abstract here: the thresholds come from the RunContext, and this
 * summary only reports breaches against them — the concrete per-suite gates are not
 * part of this layer.
 */
final readonly class AxisSummary
{
    private function __construct(
        public int $levelThreshold,
        public ?Severity $severityThreshold,
        public int $levelBreaches,
        public int $severityBreaches,
        /**
         * Security and privacy checks that did not conclude.
         *
         * Beside the breach count rather than folded into it, because they are the opposite kind of
         * news: a breach is something the run FOUND, an undetermined is something it could not
         * look at. On a managed database the second number is often the larger one, and a summary
         * that showed only breaches would report "0 breaching" for a run that answered almost
         * nothing — the silent green this package refuses, arriving as a missing column.
         */
        public int $severityUndetermined,
    ) {}

    public static function for(Result $result, RunContext $context): self
    {
        $levelBreaches = 0;
        $severityBreaches = 0;
        $severityUndetermined = 0;

        // The per-finding verdict comes from GateDecision, which owns the axis choice and the
        // never-both invariant. This used to be decided here as well, and two places deciding the
        // same thing is how a severity on a safety rule eventually becomes a level bypass: the
        // summary would have said one thing and the exit code another, out of one run.
        $level = Level::from($context->level);
        $gate = new SeverityGate($context->minSeverity);

        foreach ($result->findings as $finding) {
            $decision = GateDecision::for($finding, $level, $gate);

            if ($decision->blockedBy === GateAxis::Severity) {
                $severityBreaches++;
            } elseif ($decision->blockedBy === GateAxis::Level) {
                $levelBreaches++;
            }

            if ($decision->undetermined && $decision->axis === GateAxis::Severity) {
                $severityUndetermined++;
            }
        }

        return new self($context->level, $context->minSeverity, $levelBreaches, $severityBreaches, $severityUndetermined);
    }

    /** Did this run breach either gate? Its true does not say WHICH — the fields do. */
    public function breached(): bool
    {
        return $this->levelBreaches > 0 || $this->severityBreaches > 0;
    }

    /**
     * @return array{
     *     level_gate: array{threshold: int, breaching: int},
     *     severity_gate: array{threshold: string|null, breaching: int, undetermined: int},
     * }
     */
    public function toArray(): array
    {
        return [
            'level_gate' => [
                'threshold' => $this->levelThreshold,
                'breaching' => $this->levelBreaches,
            ],
            'severity_gate' => [
                'threshold' => $this->severityThreshold?->value,
                'breaching' => $this->severityBreaches,
                'undetermined' => $this->severityUndetermined,
            ],
        ];
    }
}
