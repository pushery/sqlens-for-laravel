<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Indexes;

use Pushery\SQLens\Rules\Coverage\ForeignKeyIndexCoverage;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * An index nobody has read — as far as counters that can be reset are able to say.
 *
 * ## The counter is easy; the WINDOW is the whole difficulty
 *
 * "This index has never been scanned" is a statement about nothing until you know how long the
 * server has been counting. Measured on PostgreSQL 18.4: on a cluster nobody has reset,
 * `pg_stat_database.stats_reset` comes back NULL — the ordinary state, and the one where a zero
 * count means only that the window started at a moment nobody recorded. MySQL has no reset point at
 * all; its counters run from server start and `performance_schema` may be switched off entirely.
 *
 * So there are three answers and only one of them is a verdict:
 *
 * - The statistics could not be read, or the window is unknown or shorter than the project's
 *   minimum ⇒ **undetermined**, with the reason named.
 * - An index the reading does not cover ⇒ **nothing**. It was not counted, which is not the same as
 *   counted and never used.
 * - A zero count over a window long enough ⇒ **a finding**, quoting the count and the window's
 *   start so a reader can check the claim themselves.
 *
 * ## Why the elapsed time is never printed
 *
 * The finding carries `stats_reset` and the configured minimum, and NOT the live "it has been 34
 * days" — because that number changes between two audits of an unchanged database, and this
 * package's reports are supposed to be diffable. The verdict does still depend on the clock, once,
 * at the threshold. That is inherent to asking a time-bounded question, and it is precisely why
 * this rule is opt-in rather than part of a default run.
 *
 * ## Never reported, whatever the counter says
 *
 * A primary key or a unique index. Dropping either changes what the schema ALLOWS, and "nobody
 * queried it" is not an argument about a constraint — the index exists to refuse a write, and it
 * has been doing that silently the whole time.
 */
final readonly class UnusedIndex
{
    /**
     * Every index on this table with a scan count of zero, and its count.
     *
     * @return array<string, int> index name => its scan count (always 0), sorted by name
     */
    public static function on(SchemaObject $table): array
    {
        $protected = [
            ...array_keys(ForeignKeyIndexCoverage::parse($table->getString('primary_key') ?? '')),
            ...array_keys(ForeignKeyIndexCoverage::parse($table->getString('unique_indexes') ?? '')),
        ];

        $unused = [];

        foreach (ForeignKeyIndexCoverage::parse($table->getString('index_scans') ?? '') as $index => $counts) {
            $count = $counts[0] ?? '';

            if ($count === '0' && ! in_array((string) $index, array_map(strval(...), $protected), true)) {
                $unused[(string) $index] = 0;
            }
        }

        ksort($unused);

        return $unused;
    }

    /**
     * Whether this table's statistics were read at all.
     *
     * An absent attribute means the reading could not be made — `performance_schema` off, a role
     * without the privilege — and NOT that no index was used. The projection leaves it absent
     * precisely so the two cannot be confused here.
     */
    public static function wasRead(SchemaObject $table): bool
    {
        return $table->hasAttribute('index_scans');
    }

    /**
     * When the server last reset the counters, as it spells it, or null when it never did.
     *
     * Null is the ordinary answer on a fresh PostgreSQL cluster and the permanent answer on MySQL.
     * It means the window starts at a moment nobody recorded, which is not a short window — it is
     * an unknown one, and the two deserve different sentences.
     */
    public static function windowStart(SchemaObject $table): ?string
    {
        $reset = $table->getString('index_stats_reset_at');

        return $reset === null || $reset === '' ? null : $reset;
    }

    /**
     * How many whole days the counters have been running, or null when nobody can say.
     *
     * Computed by the SERVER and carried here, never recomputed in PHP: the reset point and the
     * counts were stamped by one clock, and a second clock could disagree with it by more than the
     * threshold a rule compares against. `-1` is the projection's way of writing "unknown" in an
     * attribute that has to be a scalar, and it is translated back here rather than leaking out.
     */
    public static function windowDays(SchemaObject $table): ?int
    {
        $days = $table->getInt('index_stats_window_days');

        return $days === null || $days < 0 ? null : $days;
    }
}
