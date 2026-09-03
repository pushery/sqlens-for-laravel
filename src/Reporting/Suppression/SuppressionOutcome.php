<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Suppression;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Reporting\Baseline\BaselineEntry;

/**
 * What the suppression chain decided for one run: which findings still reach the
 * gate, which were hidden and by whom, and which suppression instructions turned
 * out to cover nothing at all.
 *
 * The last part is what keeps a suppression list from rotting. A baseline entry
 * or an ignore rule that matched nothing is either a finding fixed long ago or an
 * instruction that never worked — and neither is visible unless somebody counts.
 */
final readonly class SuppressionOutcome
{
    /**
     * @param  list<Finding>  $visible  the findings the gate still sees
     * @param  list<SuppressedFinding>  $suppressed
     * @param  list<BaselineEntry>  $staleBaselineEntries  recorded but matched nothing
     * @param  list<ConfigIgnoreRule>  $unusedIgnoreRules  configured but matched nothing
     */
    public function __construct(
        public array $visible,
        public array $suppressed,
        public array $staleBaselineEntries = [],
        public array $unusedIgnoreRules = [],
        /**
         * Accepted findings this run could not check at all — the source did not answer.
         *
         * Kept apart from the stale ones because the two mean opposite things to a reader.
         * "Stale" says the problem is gone and the line can go with it; this says nobody looked.
         * Telling somebody the second while showing them the first is how a baseline entry gets
         * deleted and comes straight back on the next machine that has the tool.
         *
         * @var list<BaselineEntry>
         */
        public array $unverifiableBaselineEntries = [],
    ) {}

    /**
     * How many findings each layer hid. Every source is present even at zero, so
     * the balance has a stable shape a machine consumer can rely on.
     *
     * @return array<string, int>
     */
    public function countsBySource(): array
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
}
