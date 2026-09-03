<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan;

/**
 * One thing the static pre-scan found in a migration.
 *
 * A hit always carries where it is and WHY it matters. The reason is written for
 * the person reading the report, not for the detector that produced it: a user
 * who sees "this migration is undetermined" must be able to tell, from the hit
 * alone, what in their file caused it and what to do about it.
 */
final readonly class PreScanHit
{
    public function __construct(
        public string $ruleId,
        public string $file,
        public int $line,
        public string $reason,
        public string $target,
    ) {}

    /**
     * A deterministic array projection with a fixed key order.
     *
     * @return array{rule_id: string, file: string, line: int, target: string, reason: string}
     */
    public function toArray(): array
    {
        return [
            'rule_id' => $this->ruleId,
            'file' => $this->file,
            'line' => $this->line,
            'target' => $this->target,
            'reason' => $this->reason,
        ];
    }

    /**
     * The sort key that fixes hit order — file, then line, then rule id. Two
     * detectors that both fire on the same line must still come out in a fixed
     * order, or the report differs between runs.
     */
    public function sortKey(): string
    {
        return sprintf('%s|%010d|%s', $this->file, $this->line, $this->ruleId);
    }
}
