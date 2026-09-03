<?php

declare(strict_types=1);

namespace Pushery\SQLens\Corpus;

/**
 * One loaded corpus collection.
 *
 * A value object rather than the four arrays it is made of, because the measurement has to be able
 * to name its own ground set. `$path` and `$provenance` are what a report prints so a reader can
 * tell a number derived from this package's own fixtures apart from one measured against somebody
 * else's real migrations. Those are different kinds of evidence and a single averaged figure hides
 * which one it came from.
 */
final readonly class CorpusCollection
{
    /**
     * @param  string  $path  repo-relative, e.g. `tests/Fixtures/Corpus/synthetic/pgsql-locking`
     * @param  string  $provenance  `synthetic` or `real` — read from the LAYOUT, never from a field
     * @param  array<string, string>  $manifest  validated against the closed schema
     * @param  list<array{rule_id: string, outcome: string}>  $expectations  the ground truth
     * @param  list<string>  $migrations  repo-relative migration files, sorted
     */
    public function __construct(
        public string $path,
        public string $provenance,
        public array $manifest,
        public array $expectations,
        public array $migrations,
    ) {}

    /**
     * How many entries expect each of the three verdicts.
     *
     * Part of the run context rather than a convenience: a corpus whose ground truth is 90 per cent
     * `expected_pass` measures something quite different from one that is 90 per cent
     * `expected_fail`, and a rate quoted without that shape is not comparable to the next one.
     *
     * @return array<string, int>
     */
    public function outcomeCounts(): array
    {
        $counts = array_fill_keys(CorpusFormat::EXPECTATION_CLASSES, 0);

        foreach ($this->expectations as $expectation) {
            $counts[$expectation['outcome']]++;
        }

        return $counts;
    }
}
