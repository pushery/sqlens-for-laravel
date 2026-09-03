<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Pgls;

use Pushery\SQLens\Findings\Finding;

/**
 * The result of merging the tool's findings into a run's own: what was already ours, and what only
 * the tool found.
 *
 * Two lists rather than one, because the caller needs the distinction. The own findings keep their
 * order and their identity — some now carrying a confirmation — and the additional ones are new
 * ground. Handing back a single merged array would make "did the tool change our verdicts" a
 * question nobody could answer from the return value.
 */
final readonly class PglsDeduplication
{
    /**
     * @param  list<Finding>  $own  the run's own findings, in their own order, some confirmed
     * @param  list<Finding>  $additional  what only the tool found
     */
    public function __construct(
        public array $own,
        public array $additional,
    ) {}

    /** @return list<Finding> */
    public function all(): array
    {
        return [...$this->own, ...$this->additional];
    }
}
