<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\OnlineDdl;

use Pushery\SQLens\Findings\DowntimeClass;

/**
 * The one bridge from a resolved matrix entry to a `downtime_class`. Given a
 * {@see MatrixResolution}, it returns the deploy class (online / blocking / rewrite) or passes
 * the resolver's named undetermined straight through.
 *
 * This is the ONLY place in the MySQL driver that turns the matrix axes into a class. The MySQL
 * rule set wires rule → resolver → this mapper → finding field; the rules never grow a second
 * classifier, or two decision tables would sit side by side and drift. An arch test enforces
 * that no code under the MySQL driver outside this namespace reads `algorithm`,
 * `rebuilds_table`, `permits_concurrent_dml`, or `lock` to decide a class.
 *
 * The decision is a total function of three axes — algorithm, then, for INPLACE only, whether
 * it rebuilds the table and whether it permits concurrent DML:
 *
 * - INSTANT is always online — a metadata change that returns at once.
 * - COPY is always a rewrite — the whole table is rebuilt.
 * - INPLACE is the ambiguous one, decided explicitly, and in this order:
 *   (NOT APPLICABLE takes the same branch, for the reason below.)
 *   - it REBUILDS the table → rewrite. The class is defined by what the operation does to the
 *     table, not by what it happens to permit while doing it: an in-place rebuild copies every
 *     row, takes the time and the disk space of a rewrite, and ends under a metadata lock. Some
 *     in-place rebuilds do let writes through, and calling those "blocking" would both misname
 *     them and rank them BELOW a rewrite they cost exactly as much as — an understatement, which
 *     is the one direction this package must never err in.
 *   - it does not rebuild but BLOCKS concurrent writes → blocking. This is the case the class
 *     exists for: cheap in bytes, unavailable in writes, for as long as it runs.
 *   - neither → online.
 *
 * The `lock` axis is deliberately NOT a separate input: a shared or exclusive lock is the very
 * thing that makes `permits_concurrent_dml` false, so the two are one fact in two spellings, and
 * deciding on the boolean keeps the table free of an impossible "writes allowed under an
 * exclusive lock" cell.
 *
 * ## An operation the ALGORITHM clause does not decide is still decided
 *
 * A handful of partitioning statements take no meaningful `ALGORITHM` — either the grammar
 * refuses the clause outright or it parses it and ignores it (see
 * {@see OnlineDdlAlgorithm::NotApplicable}). The temptation is to call those undetermined, and
 * it would be wrong: the algorithm was never the fact, it was a PROXY for two facts. Whether
 * the operation rebuilds the table and whether writes flow while it runs are measured directly
 * for those entries — by watching the InnoDB tablespace ids and by writing from a second
 * session mid-statement — so the same three-axis rule applies with one input fewer, and
 * reporting `undetermined` would throw away an answer that was actually taken from the server.
 *
 * The direction that WOULD be wrong is the optimistic one. An operation the matrix does not
 * classify at all never reaches this mapper as an entry: the resolver returns a named
 * undetermined and it is passed straight through, because "we have no row for this" must never
 * come out as `online`.
 */
final readonly class DowntimeClassMapper
{
    public function map(MatrixResolution $resolution): DowntimeClassMapping
    {
        $entry = $resolution->entry;

        if (! $entry instanceof MatrixEntry) {
            return DowntimeClassMapping::undetermined($resolution->reason, $resolution->detail);
        }

        return DowntimeClassMapping::determined($this->classify($entry));
    }

    private function classify(MatrixEntry $entry): DowntimeClass
    {
        return match ($entry->algorithm) {
            OnlineDdlAlgorithm::Instant => DowntimeClass::Online,
            OnlineDdlAlgorithm::Copy => DowntimeClass::Rewrite,
            OnlineDdlAlgorithm::Inplace, OnlineDdlAlgorithm::NotApplicable => match (true) {
                $entry->rebuildsTable => DowntimeClass::Rewrite,
                ! $entry->permitsConcurrentDml => DowntimeClass::Blocking,
                default => DowntimeClass::Online,
            },
        };
    }
}
