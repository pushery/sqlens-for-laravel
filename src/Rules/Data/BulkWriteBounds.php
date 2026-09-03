<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Data;

/**
 * Whether an engine can see a bound on how many rows a data statement will touch.
 *
 * The HAZARD is the same on both engines — an unbounded backfill writes however many rows the table
 * happens to hold — but the SIGNAL is not, and that asymmetry is the reason this is an interface
 * rather than one shared function.
 *
 * Measured against both grammars: MySQL supports `UPDATE … LIMIT n` and Laravel emits it verbatim
 * from `->limit(1000)`. PostgreSQL has no such clause, and the framework compiles the same call as
 * `WHERE "ctid" IN (SELECT "t"."ctid" FROM "t" WHERE … LIMIT n)` — a different statement shape
 * entirely. A shared reader would have to look for both on both engines, which would mean each one
 * accepting a bound its own server cannot express.
 */
interface BulkWriteBounds
{
    /**
     * Whether this statement carries something that bounds the rows it touches.
     *
     * `$isRowSource` is here because the same keyword means different things on the two shapes. A
     * top-level `LIMIT` on an `INSERT … SELECT` bounds the write on BOTH engines — that is ordinary
     * SQL, and it is what a chunked copy looks like. On an `UPDATE`/`DELETE` it is MySQL-only, and
     * on PostgreSQL a `LIMIT` can only ever appear inside a subquery, where it bounds the subquery
     * and says nothing about the rows written.
     *
     * @param  string  $masked  the canonical statement with its string literals blanked out — see
     *                          {@see BulkWrite::parse()} for why that matters
     * @param  bool  $isRowSource  whether the rows come from a query (`INSERT … SELECT`) rather than
     *                             from a predicate on the target table
     */
    public function bounds(string $masked, bool $isRowSource): bool;
}
