<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Squawk;

use Pushery\SQLens\Findings\Finding;

/**
 * The outcome of merging a tool's findings into a run's own: the run's findings, unchanged in
 * number and identity, plus the ones only the tool found.
 *
 * Two lists rather than one merged list, because the difference matters to everything
 * downstream. The gate reads them differently, the report shows them differently, and a single
 * flattened list would make "did the tool change our verdict?" a question nobody can answer
 * without re-running without it.
 */
final readonly class SquawkDeduplication
{
    /**
     * @param  list<Finding>  $own  the run's own findings, in their original order — some now
     *                              carrying a confirmation. The COUNT is invariant: a tool can
     *                              never remove one of ours, and this list is where that promise
     *                              is either kept or broken.
     * @param  list<Finding>  $additional  what only the tool found — the amplification itself
     */
    public function __construct(
        public array $own,
        public array $additional,
    ) {}

    /**
     * Everything the report shows, ours first.
     *
     * @return list<Finding>
     */
    public function all(): array
    {
        return [...$this->own, ...$this->additional];
    }
}
