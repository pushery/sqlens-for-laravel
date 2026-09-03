<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Statistics;

/**
 * What is known about the age of the statistics behind a number.
 *
 * Four cases, and the two that look redundant are the ones carrying the package's first principle
 * into the statistics channel. "The server says no ANALYZE has ever run" and "we could not find
 * out when it ran" arrive at the same place — no timestamp — and collapsing them there would be a
 * silent green of exactly the shape this package refuses everywhere else: an unmeasured thing
 * reported as a measured one.
 *
 * They also call for opposite actions. `NeverCollected` is fixed by running ANALYZE. `Unknown` is
 * fixed by granting a privilege, or not at all on a managed database that withholds the view — and
 * telling a project to ANALYZE a table whose statistics are fine is how a tool loses the reader.
 */
enum EstimateFreshness: string
{
    /** The server named a moment: the statistics behind this number were refreshed then. */
    case Measured = 'measured';

    /**
     * The server states that no statistics run has ever happened for this object.
     *
     * A positive fact rather than an absence of one, and PostgreSQL says it outright: since 14,
     * `pg_class.reltuples` is -1 for a relation that has never been vacuumed or analyzed. The
     * number a consumer holds is therefore weak in a way that is knowable, and marked as such.
     */
    case NeverCollected = 'never_collected';

    /**
     * The freshness could not be established — a privilege, a withheld view, an engine that does
     * not report it.
     *
     * The ordinary case on MySQL, where the row count reads fine while the moment its statistics
     * were last refreshed is not generally available. Ordinary is not the same as harmless: a
     * number of unknown age is exactly as usable as a number of known age, right up until somebody
     * decides something on it.
     */
    case Unknown = 'unknown';

    /**
     * There are no statistics behind this number, so it has no age.
     *
     * The exact-at-read-time sources — PostgreSQL's size functions compute their answer while
     * answering. Distinct from `Unknown` because it is the opposite state: not "we failed to find
     * out" but "there is nothing there to find out", and the two must not read alike in a report.
     */
    case NotApplicable = 'not_applicable';
}
