<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

/**
 * What the exclude file did to a drift report.
 *
 * Three values rather than one, and the second is why this type exists at all: the FILTERED report,
 * how many differences were withdrawn, and which entries matched nothing.
 *
 * A caller that only received the filtered report would have no honest way to say "and four
 * differences you accepted are not shown" — so the count travels with the result rather than being
 * recoverable by subtracting two numbers a reader does not have.
 */
final readonly class DriftExcludeOutcome
{
    /**
     * @param  list<DriftExcludeEntry>  $stale  entries that covered nothing this run
     */
    public function __construct(
        public DriftReport $report,
        public int $excluded,
        public array $stale,
    ) {}
}
