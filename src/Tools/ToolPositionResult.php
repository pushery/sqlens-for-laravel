<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

/**
 * A mapped position, or the named reason there is none.
 *
 * The degradation is per FINDING, never per run: a tool that reported one position this package
 * cannot place has still said something useful about the others, and dropping the whole report
 * for it would cost more than the one finding is worth.
 */
final readonly class ToolPositionResult
{
    /**
     * The stable public identifier of this degradation.
     *
     * One id for all four causes: what a reader has to act on is that a finding could not be
     * placed. The cause is the detail behind it, the way every named reason in this package
     * carries a detail — a public id per internal cause would make the cause set public API.
     */
    private function __construct(
        public ?ToolPosition $position,
        public ?ToolPositionUnmappable $unmappable,
    ) {}

    public static function at(ToolPosition $position): self
    {
        return new self($position, null);
    }

    public static function unmappable(ToolPositionUnmappable $cause): self
    {
        return new self(null, $cause);
    }

    public function isMapped(): bool
    {
        return $this->position instanceof ToolPosition;
    }
}
