<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Severity\Severity;

/**
 * What a statistic did to a finding's severity, said out loud.
 *
 * ## Why the raise is recorded rather than just applied
 *
 * A finding that arrives as `critical` looks exactly like a finding that was WRITTEN as critical.
 * Without this record a reader has no way to tell a rule's own verdict from one a row estimate
 * raised — and the two deserve different responses. A rule's verdict is about the migration; a raise
 * is about this database on this day, and it moves when somebody runs `ANALYZE`.
 *
 * That distinction is also what keeps the escalation honest under review. The threshold that fired
 * travels with the finding, so "why is this critical" has an answer that does not require reading
 * the shipped artefact and guessing which step matched.
 *
 * ## Why the base severity is kept
 *
 * Suppressing or baselining a finding is done against what the RULE said. If the record only carried
 * the raised value, a baseline written on Monday would stop matching on Friday because a table grew
 * — a suppression that silently expires is worse than one that never existed.
 */
final readonly class Escalation
{
    /**
     * @param  'rows'|'bytes'  $unit  what the threshold is measured in — part of the claim, because
     *                                a rewrite is bounded by bytes and an index build by rows
     */
    public function __construct(
        public Severity $baseSeverity,
        public Severity $escalatedSeverity,
        public string $operation,
        public int $threshold,
        public string $unit,
    ) {}

    /**
     * @return array{
     *     escalated: true,
     *     base_severity: string,
     *     escalated_severity: string,
     *     operation: string,
     *     threshold: array{value: int, unit: string},
     * }
     */
    public function toArray(): array
    {
        return [
            // A literal `true` rather than a computed flag. This object only exists when a raise
            // happened, so the key is present exactly when it is true — and a consumer filtering on
            // it never has to decide what `escalated: false` would have meant.
            'escalated' => true,
            'base_severity' => $this->baseSeverity->value,
            'escalated_severity' => $this->escalatedSeverity->value,
            'operation' => $this->operation,
            'threshold' => ['value' => $this->threshold, 'unit' => $this->unit],
        ];
    }
}
