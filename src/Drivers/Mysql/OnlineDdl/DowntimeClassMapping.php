<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\OnlineDdl;

use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\DowntimeUndetermined;
use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * The outcome of mapping a resolved matrix entry to a deploy decision: either a
 * {@see DowntimeClass}, or the named undetermined the resolver already produced, passed through
 * unchanged. An undetermined matrix resolution is never pressed into a class — "we could not
 * classify this" and "this is online" are different statements, and only one is a verdict.
 */
final readonly class DowntimeClassMapping
{
    private function __construct(
        public ?DowntimeClass $downtimeClass,
        public ?UndeterminedReason $reason,
        public ?string $detail = null,
    ) {}

    public static function determined(DowntimeClass $downtimeClass): self
    {
        return new self($downtimeClass, null);
    }

    public static function undetermined(?UndeterminedReason $reason, ?string $detail): self
    {
        return new self(null, $reason, $detail);
    }

    public function isDetermined(): bool
    {
        return $this->downtimeClass instanceof DowntimeClass;
    }

    /**
     * What a finding carries: the class, or the undetermined with the reason the resolver gave. A
     * rule that returned the class alone dropped that reason, and its finding then read as making
     * no claim about downtime at all.
     */
    public function derived(): DowntimeClass|DowntimeUndetermined
    {
        return $this->downtimeClass ?? new DowntimeUndetermined($this->reason ?? UndeterminedReason::OnlineDdlConditionUndecidable, $this->detail);
    }
}
