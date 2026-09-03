<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Statistics;

use Pushery\SQLens\Exceptions\InvalidStatisticsReading;

/**
 * How big one table is, as far as the server will say.
 *
 * Four numbers and a list, and each slot is checked against the quantity it is supposed to hold.
 * The check is not defensive programming for its own sake: every number here is the same type, so
 * nothing but this stops a size landing in the row slot — and a finding weighted by a byte count it
 * believes is a row count is off by roughly the width of a row, silently, in the direction that
 * escalates.
 *
 * **Null is not zero, anywhere on this object.** A number the reading could not establish is
 * absent, and the snapshot carries a named skip saying why. Zero rows is a table somebody emptied;
 * no row count is a question nobody could answer, and a gate that treated the second as the first
 * would wave through the migration it exists to weight.
 *
 * The "when were these statistics last refreshed" the deploy suite needs is NOT a field here. It
 * lives inside each {@see Estimate}, because the numbers do not share an answer: on an engine that
 * computes sizes while it answers, the byte counts have no staleness at all while the row count is
 * as old as the last statistics run. One field would have had to be wrong about one of them.
 */
final readonly class TableStatistics
{
    /** @var list<IndexStatistics> */
    public array $indexes;

    /** @param  list<IndexStatistics>  $indexes */
    public function __construct(
        /** The table, qualified as the reading names it — the key everything else joins on. */
        public string $qualifiedName,
        /** Live rows, always an estimate; null when the reading established none. */
        public ?Estimate $rows = null,
        /** Bytes the table's own storage occupies, without its indexes. */
        public ?Estimate $tableBytes = null,
        /** Bytes all its indexes occupy together. */
        public ?Estimate $indexBytes = null,
        /** Bytes the table occupies in total — storage, indexes and the engine's overhead. */
        public ?Estimate $totalBytes = null,
        array $indexes = [],
    ) {
        $this->mustMeasure('row count', $rows, EstimateSource::RowCount);
        $this->mustMeasure('table size', $tableBytes, EstimateSource::TableBytes);
        $this->mustMeasure('index size', $indexBytes, EstimateSource::IndexBytes);
        $this->mustMeasure('total size', $totalBytes, EstimateSource::TotalBytes);

        // Sorted here rather than left to the reader's query, for the reason the catalog snapshot
        // sorts its objects: two readings of an unchanged table must serialize byte-identically, or
        // a drift comparison reports the ordering of a query plan as a schema change.
        usort($indexes, static fn (IndexStatistics $a, IndexStatistics $b): int => $a->qualifiedName <=> $b->qualifiedName);

        $this->indexes = $indexes;
    }

    /** Whether the reading established anything at all about this table. */
    public function isEmpty(): bool
    {
        return ! $this->rows instanceof Estimate
            && ! $this->tableBytes instanceof Estimate
            && ! $this->indexBytes instanceof Estimate
            && ! $this->totalBytes instanceof Estimate
            && $this->indexes === [];
    }

    /**
     * Whether any number here rests on statistics that were never collected.
     *
     * Three-valued, and the null is the answer worth having: at least one freshness could not be
     * read and nothing else was stale, so the reading cannot be certified either way. Answering
     * `false` there would report statistics nobody looked at as sound — and this is the value a
     * severity escalation reads before deciding how much to trust its own weighting.
     */
    public function isStale(): ?bool
    {
        $undetermined = false;

        foreach ($this->estimates() as $estimate) {
            $stale = $estimate->isStale();

            if ($stale === true) {
                return true;
            }

            if ($stale === null) {
                $undetermined = true;
            }
        }

        return $undetermined ? null : false;
    }

    /**
     * @return array{name: string, rows: array<string, mixed>|null, table_bytes: array<string, mixed>|null, index_bytes: array<string, mixed>|null, total_bytes: array<string, mixed>|null, indexes: list<array<string, mixed>>}
     */
    public function toArray(): array
    {
        return [
            'name' => $this->qualifiedName,
            'rows' => $this->rows?->toArray(),
            'table_bytes' => $this->tableBytes?->toArray(),
            'index_bytes' => $this->indexBytes?->toArray(),
            'total_bytes' => $this->totalBytes?->toArray(),
            'indexes' => array_map(static fn (IndexStatistics $index): array => $index->toArray(), $this->indexes),
        ];
    }

    /** @return list<Estimate> every number present, table-level ones first, then the indexes' */
    private function estimates(): array
    {
        $estimates = array_values(array_filter(
            [$this->rows, $this->tableBytes, $this->indexBytes, $this->totalBytes],
            static fn (?Estimate $estimate): bool => $estimate instanceof Estimate,
        ));

        foreach ($this->indexes as $index) {
            if ($index->bytes instanceof Estimate) {
                $estimates[] = $index->bytes;
            }
        }

        return $estimates;
    }

    private function mustMeasure(string $slot, ?Estimate $estimate, EstimateSource $expected): void
    {
        if ($estimate instanceof Estimate && $estimate->source !== $expected) {
            throw InvalidStatisticsReading::wrongQuantity($slot, $expected, $estimate->source);
        }
    }
}
