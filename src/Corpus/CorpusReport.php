<?php

declare(strict_types=1);

namespace Pushery\SQLens\Corpus;

/**
 * The measurement, as a committed artifact.
 *
 * ## Why a file rather than console output
 *
 * A number on a terminal is gone when the terminal is. The release gate reads this file to refuse a
 * version whose rules moved since the last measurement, and a reviewer reads its DIFF to see which
 * rule got noisier. Neither is possible with a printed summary.
 *
 * ## Determinism is the survival condition, not a nicety
 *
 * A generator that leaked a timestamp into the content would produce a diff on every run. Committed
 * artifacts that always differ read as noise, a team stops reading them, and at that point every
 * other guarantee in the chain is worth nothing — the report would still be generated and nobody
 * would look.
 *
 * So the content carries no clock. The RUN block records what the measurement depended on — the
 * collections it read, their provenance, the ground-truth shape — and the timestamp belongs to the
 * commit that changed the file, which git already keeps and keeps better.
 *
 * ## The ground set is part of the result
 *
 * Every collection is named, with how many expectations of each verdict it contributed. A rate over
 * a corpus nobody can enumerate is a rate nobody can reproduce, and two rates over different corpora
 * are not comparable however similar the percentages look.
 */
final readonly class CorpusReport
{
    /**
     * The schema version of this artifact.
     *
     * Consumers of a committed report — the release gate, a future comparison across versions — need
     * to know when its shape changed. Bumped when a field is removed or its meaning moves, never for
     * an addition.
     */
    public const int SCHEMA_VERSION = 1;

    /**
     * Build the report body.
     *
     * @param  list<CorpusCollection>  $collections
     * @return array<string, mixed>
     */
    public static function of(CorpusMetrics $metrics, array $collections, ?string $ruleCatalogHash = null): array
    {
        return [
            'schema_version' => self::SCHEMA_VERSION,
            // WHICH rule catalog this rate describes. A false-positive rate is a statement about a
            // set of rules, and a rate published beside a catalog that has since gained six rules
            // is a number about a package that no longer exists — read as current, because nothing
            // in the file says otherwise.
            //
            // Nullable only for a report written before this field existed; the release gate treats
            // its absence as "cannot be compared", which is red rather than green.
            'rule_catalog' => $ruleCatalogHash === null ? null : ['hash' => $ruleCatalogHash],
            'ground_set' => self::groundSet($collections),
            'summary' => [
                // Null when nothing could be measured, and null is NOT zero: zero reads as "no
                // false positives", which is the best possible result rather than the absence of
                // one.
                'false_positive_rate' => $metrics->falsePositiveRate(),
                'measured' => $metrics->measured(),
                // Beside the rate, never inside it. Every failure mode of a corpus run lands here,
                // and each would otherwise improve the rate by shrinking its denominator.
                'unmeasured' => $metrics->unmeasured(),
                'counts' => $metrics->counts,
            ],
            'by_rule' => $metrics->byRule,
            'by_driver' => $metrics->byDriver,
            'by_level' => $metrics->byLevel,
            // Named rather than counted. A high score over a narrow slice reads as coverage unless
            // the slice is stated, and these are the rules the number says nothing about.
            'blind_spots' => $metrics->blindSpots,
        ];
    }

    /**
     * What the measurement was made over.
     *
     * @param  list<CorpusCollection>  $collections
     * @return list<array<string, mixed>>
     */
    private static function groundSet(array $collections): array
    {
        $entries = [];

        foreach ($collections as $collection) {
            $entries[] = [
                'path' => $collection->path,
                'provenance' => $collection->provenance,
                'engine' => $collection->manifest['engine'],
                'corpus_version' => $collection->manifest['corpus_version'],
                // The hash of the rule catalog this collection was last annotated against. It is
                // what lets a reader tell a fresh report from one describing a rule set that has
                // since moved — without it a stale measurement reads exactly like a current one.
                'rule_catalog_hash' => $collection->manifest['rule_catalog_hash'],
                'migrations' => count($collection->migrations),
                'expectations' => $collection->outcomeCounts(),
            ];
        }

        // Sorted by path so two runs over one corpus produce byte-identical output. The loader
        // already sorts; doing it again here means a caller assembling the list differently cannot
        // silently reintroduce a diff nobody can explain.
        usort($entries, static fn (array $a, array $b): int => strcmp((string) $a['path'], (string) $b['path']));

        return $entries;
    }
}
