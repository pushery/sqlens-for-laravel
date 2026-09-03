<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L3\Support;

/**
 * MySQL's timeout vocabulary — its OWN, not a translation of PostgreSQL's.
 *
 * PostgreSQL bounds a migration with two client settings that pair neatly: `lock_timeout` caps the
 * wait in the lock queue, `statement_timeout` caps the run. MySQL has neither of those names and
 * does not have that pairing, and the names it does have look close enough to be mistaken for it.
 * This class exists so the mistake has to be made deliberately.
 *
 * ## The three settings, and what each one actually bounds
 *
 * - **`lock_wait_timeout`** — how long a statement waits for a **metadata lock**, in SECONDS. This
 *   is the one a DDL migration must set, and the default is **31536000** — one year, which is
 *   "forever" for every purpose a migration has. That default is why its absence is a finding
 *   rather than a preference.
 * - **`innodb_lock_wait_timeout`** — how long a statement waits for a **row lock**, in seconds,
 *   default 50. A different lock, taken by DML rather than by DDL. Setting it does not bound a
 *   `ALTER TABLE` waiting on the metadata lock, so it may not be counted as satisfying the rule.
 * - **`max_execution_time`** — MILLISECONDS, and **read-only SELECT statements only**. It is not a
 *   `statement_timeout`, and recommending it in a DDL preamble would promise a bound that does not
 *   apply to the statement it is written above.
 *
 * ## The last one is MEASURED, because it is the expensive mistake
 *
 * Against a real MySQL 8.4.10, under `SET max_execution_time=200`:
 *
 * - the same work as a `SELECT` with real table access was killed after 235 ms with
 *   `ER_QUERY_TIMEOUT` (`ERROR 3024: maximum statement execution time exceeded`);
 * - the same work wrapped in `DO (…)` — a non-SELECT — ran **612 seconds** and was never
 *   interrupted. It had to be killed by hand.
 *
 * Two earlier attempts measured nothing and are recorded because they look like evidence:
 * `SELECT SLEEP(3)` and `SELECT BENCHMARK(…)` both ran to completion under the same 200 ms limit.
 * Without a positive control the `DO` result would have "proved" the point while only showing that
 * a query had been chosen which the limit never reaches.
 *
 * ## What MySQL does NOT have
 *
 * There is no counterpart to `statement_timeout` for DDL. That is a property of the engine, not a
 * gap in this package, and it is named in the rule's `limitations()` rather than papered over with
 * the setting whose name is closest.
 */
final readonly class MysqlTimeouts
{
    /** Caps the wait for a METADATA lock, in seconds. The one a DDL migration must set. */
    public const string LOCK_WAIT_TIMEOUT = 'lock_wait_timeout';

    /** Caps the wait for a ROW lock, in seconds. A different lock; never counts for DDL. */
    public const string INNODB_LOCK_WAIT_TIMEOUT = 'innodb_lock_wait_timeout';

    /** Read-only SELECT statements only, in milliseconds. Measured: does not bound a non-SELECT. */
    public const string MAX_EXECUTION_TIME = 'max_execution_time';

    /**
     * The server default for {@see self::LOCK_WAIT_TIMEOUT}, in seconds — one year.
     *
     * Carried as a number rather than as prose because it is the whole argument: a setting whose
     * default is a year is not "already bounded", and a reader who assumes MySQL has a sane default
     * here is the reader this rule is written for.
     */
    public const int LOCK_WAIT_TIMEOUT_DEFAULT_SECONDS = 31536000;
}
