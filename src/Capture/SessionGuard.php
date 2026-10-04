<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Closure;
use Illuminate\Database\Connection;
use Pdo\Pgsql as PdoPgsql;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Contracts\SessionDefense;
use Throwable;

/**
 * Bounds the capture's OWN session before it asks the database anything.
 *
 * This is the second half of "first, do no harm". A lint run may point at a
 * production connection, and a query without a time budget can sit behind a lock
 * indefinitely — holding up the very traffic the run was meant to protect. Even a
 * catalog read gets a budget.
 *
 * Session or transaction scope only. The tool never changes a global, and it never takes a lock
 * of its own; it only limits how long IT is willing to wait.
 *
 * The statements are per-engine, but the class stays driver-neutral: it switches
 * on the connection's driver KEY, never on a driver class, so the capture
 * namespace keeps importing nothing from `Drivers\Pgsql` or `Drivers\Mysql`.
 *
 * ## PostgreSQL: the bound lives in a transaction, never in the session
 *
 * Behind a transaction pooler a session `SET` lands on whichever backend carried that one
 * statement and stays there. PgBouncer's `server_reset_query` runs only in session pooling by
 * default, and `track_extra_parameters` cannot reset a parameter the server does not announce,
 * which `statement_timeout` and `lock_timeout` are not. The restore then looks for the setting on
 * a backend that never had it, and the next client handed the first backend inherits a timeout
 * it never chose.
 *
 * Asking `pg_backend_pid()` twice before writing could not settle that. A changed backend proves
 * multiplexing, but the same backend twice proves nothing, and under load it is the common answer:
 * measured behind PgBouncer with three clients reading through a pool of three, a backend kept
 * `lock_timeout = 3s`, which is this guard's lock budget, after the lint run that set it had
 * restored it.
 *
 * So on PostgreSQL {@see self::bind()} writes nothing at all, and the reads that need a bound get
 * it from {@see self::within()}: one transaction, both budgets as `SET LOCAL`, the reads, then a
 * rollback. A pooler keeps a transaction on one backend from its first statement to its last,
 * `SET LOCAL` ends with the transaction, and the rollback ends it whether the reads succeeded or
 * not. A host that is already inside a transaction of its own gets a savepoint instead, and rolling
 * back to the savepoint takes both settings off again, so its transaction carries on with exactly
 * what it had.
 *
 * Inside that window no statement is prepared under a name. PDO can remove a named statement with a
 * plain `DEALLOCATE`, a pooler that tracks prepared statements renamed it on the way to the server,
 * the server refuses the `DEALLOCATE`, and inside a transaction that refusal aborts it: the next
 * read fails with `25P02`, far from its cause. The connection's own setting for this is read first
 * and put back afterwards.
 *
 * ## Why this is NOT a duplicate of `SessionDefense`, and why it sets LESS
 *
 * {@see SessionDefense} bounds a session too, and on MySQL the two
 * emit byte-identical statements. On PostgreSQL this one deliberately sets two settings fewer,
 * and the difference is the CONNECTION'S OWNER rather than an oversight:
 *
 *   - `SessionDefense` bounds a reader session **this package opened**. Nothing is given back, so
 *     every bound is free.
 *   - `SessionGuard` bounds the **host application's** connection, borrowed and returned. Every
 *     setting written here is one the host must get back unchanged — through
 *     {@see self::snapshot()} and {@see self::restore()} on MySQL, through the rollback on
 *     PostgreSQL — and two of them are not merely inconvenient to give back, they are harmful to
 *     set at all.
 *
 * **`idle_in_transaction_session_timeout` — MEASURED on PostgreSQL 18.4, not reasoned.** A host
 * that is inside its own transaction when a lint run borrows the connection gets that transaction
 * DESTROYED:
 *
 *     BEGIN; INSERT …                                  -- the host's work
 *     SET idle_in_transaction_session_timeout='1000ms'  -- what a "fix" would add here
 *     (host idles 2.5s, as an application may)
 *     SELECT …  ->  FATAL: terminating connection due to idle-in-transaction timeout
 *
 * The row is gone and the connection with it. And the setting could never have helped: the one
 * transaction SQLens opens on this connection is the window of {@see self::within()}, which runs
 * its reads and ends, so the session it guards never sits idle in a transaction of SQLens's own
 * making. A bound with no upside and a measured downside is not a gap.
 *
 * **`application_name`** is the same family, one notch quieter: it is how a DBA reads
 * `pg_stat_activity` and tells whose session is whose. Writing `sqlens` onto a borrowed connection
 * relabels the HOST's session, and under Octane or a queue worker it outlives the run — so the
 * operator's own label is what SQLens would be hiding.
 *
 * `tests/Unit/Capture/SessionStatementParityTest.php` holds the two statement sets to each other
 * and names exactly these two as declared differences. Anything else drifting apart turns it red.
 */
final readonly class SessionGuard
{
    /**
     * @param  array{statement_timeout: int, lock_timeout: int}  $budget  milliseconds
     */
    public function __construct(private array $budget) {}

    /**
     * Snapshot, bound, and hand back the undo — the whole borrowing, in one call.
     *
     * One entry point rather than three, because the three have an order that is easy to get wrong
     * (`snapshot()` before `apply()`, or the snapshot records this guard's own bound). A caller that
     * arranged them by hand could get it wrong and leave the connection worse than it found it.
     *
     * On PostgreSQL it writes nothing and hands back a restore that does nothing. A session `SET` on
     * a borrowed PostgreSQL connection is the leak described above, and no probe can tell in advance
     * whether a pooler is there to cause it. The reads that need a bound take it from
     * {@see self::within()}.
     *
     * @return Closure(): void the restore, a no-op when nothing was written
     */
    public function bind(Connection $connection): Closure
    {
        if ($connection->getDriverName() === 'pgsql') {
            return static function (): void {};
        }

        // Snapshot BEFORE applying, or the snapshot records our own bound and "restoring" would
        // cement exactly what it is supposed to undo.
        $snapshot = $this->snapshot($connection);

        $this->apply($connection);

        return fn () => $this->restore($connection, $snapshot);
    }

    /**
     * Run `$work` with the borrowed session bounded, and leave nothing behind, whether it returns or
     * throws.
     *
     * On PostgreSQL the bound is transaction-local, see the class docblock. On every other engine it
     * is {@see self::bind()} around the work, so MySQL gets the same snapshot, bound and restore as
     * before, and an engine this guard cannot bound gets the work alone.
     *
     * @template TResult
     *
     * @param  Closure(): TResult  $work
     * @return TResult
     */
    public function within(Connection $connection, Closure $work): mixed
    {
        if ($connection->getDriverName() === 'pgsql') {
            return $this->withinTransaction($connection, $work);
        }

        $release = $this->bind($connection);

        try {
            return $work();
        } finally {
            $release();
        }
    }

    /**
     * The PostgreSQL window: a transaction, both budgets as `SET LOCAL`, the work, a rollback.
     *
     * A rollback rather than a commit, because the window only reads and a rollback is what undoes a
     * `SET LOCAL` inside a savepoint. A commit there would only release the savepoint and leave both
     * settings on the host's own transaction until it ends.
     *
     * @template TResult
     *
     * @param  Closure(): TResult  $work
     * @return TResult
     */
    private function withinTransaction(Connection $connection, Closure $work): mixed
    {
        $restorePrepares = $this->withoutNamedStatements($connection);

        // Only calls inside the two `try` blocks, and the loop in a method of its own: line coverage
        // reports a branch inside a `try` as run whether it ran or not.
        try {
            $connection->beginTransaction();

            try {
                $this->applyTransactionBudget($connection);

                return $work();
            } finally {
                $this->rollBackQuietly($connection);
            }
        } finally {
            $restorePrepares();
        }
    }

    /** Both budgets as `SET LOCAL`, inside the transaction the window has just opened. */
    #[RawSql(reason: 'transaction-local SET statements; the query builder has no verb for SET, and every value here is one of this package own bounded constants')]
    private function applyTransactionBudget(Connection $connection): void
    {
        foreach ($this->transactionStatementsFor('pgsql') as $statement) {
            $connection->statement($statement);
        }
    }

    /**
     * Send the window's statements without a named prepared statement, and hand back what puts the
     * connection's own setting back.
     *
     * The attribute is a property of the PHP connection object and never reaches the server, so
     * changing it for the window and back leaves nothing on any backend.
     *
     * @return Closure(): void
     */
    private function withoutNamedStatements(Connection $connection): Closure
    {
        $pdo = $connection->getPdo();
        $before = $pdo->getAttribute(PdoPgsql::ATTR_DISABLE_PREPARES);

        $pdo->setAttribute(PdoPgsql::ATTR_DISABLE_PREPARES, true);

        return static function () use ($pdo, $before): void {
            $pdo->setAttribute(PdoPgsql::ATTR_DISABLE_PREPARES, $before);
        };
    }

    /**
     * End the window, and swallow a rollback the connection cannot perform.
     *
     * The reads have already answered or already thrown, and a failure here must not replace either.
     * A connection that cannot roll back is gone, and a session that ended takes its `SET LOCAL`
     * with it.
     */
    private function rollBackQuietly(Connection $connection): void
    {
        try {
            $connection->rollBack();
        } catch (Throwable) {
            // Nothing left to undo — see above.
        }
    }

    /**
     * Apply the budget. Returns the statements it ran, so a caller can show them
     * as run parameters — a limit the user cannot see is one they cannot trust.
     *
     * An engine with no known way to bound a session is left alone rather than
     * being sent a statement that might mean something else there.
     *
     * @return list<string>
     */
    #[RawSql(reason: 'session defenses are SET statements; the query builder has no verb for SET, and every value here is one of this package own bounded constants')]
    public function apply(Connection $connection): array
    {
        $statements = $this->statementsFor($connection->getDriverName());

        foreach ($statements as $statement) {
            $connection->statement($statement);
        }

        return $statements;
    }

    /**
     * The values this guard is about to overwrite, so a caller can put them back.
     *
     * The bound belongs to the RUN, not to the connection. On a short-lived Artisan
     * process that distinction is invisible — the connection dies at exit — but SQLens
     * writes onto the HOST APPLICATION's connection, and under Octane, a queue worker or
     * a test suite that object outlives the run. Leaving a 5-second statement_timeout
     * behind would make an unrelated query fail later for a reason the application never
     * chose: harm caused by the mechanism that exists to prevent harm.
     *
     * Read back per engine and left EMPTY for an engine this guard does not bound — there
     * is then nothing to restore, and asking would be a query for no reason.
     *
     * @return array<string, string> setting => the value in force before apply()
     */
    public function snapshot(Connection $connection): array
    {
        return match ($connection->getDriverName()) {
            'pgsql' => [
                'statement_timeout' => $this->currentSetting($connection, 'SHOW statement_timeout'),
                'lock_timeout' => $this->currentSetting($connection, 'SHOW lock_timeout'),
            ],
            'mysql' => [
                'max_execution_time' => $this->currentSetting($connection, 'SELECT @@SESSION.max_execution_time AS v'),
                'innodb_lock_wait_timeout' => $this->currentSetting($connection, 'SELECT @@SESSION.innodb_lock_wait_timeout AS v'),
                'lock_wait_timeout' => $this->currentSetting($connection, 'SELECT @@SESSION.lock_wait_timeout AS v'),
            ],
            default => [],
        };
    }

    /**
     * Put a snapshot back. A restore that cannot run is swallowed deliberately: the run
     * is over and its result already stands, so throwing here would turn a completed lint
     * into a crash over housekeeping. The connection dying is itself the restore.
     *
     * That swallow is why the literal form below has to be right per engine rather than
     * merely plausible. Measured on MySQL 8.4: `SET SESSION max_execution_time = '0'` is
     * refused with error 1232, "Incorrect argument type to variable" — MySQL takes the bare
     * numeric form for a numeric system variable, and the quoted one is a type error. The
     * swallow would then make a total failure to restore look exactly like a successful one, and
     * every lint run would leave `max_execution_time = 5000` and `innodb_lock_wait_timeout = 3`
     * behind on the host application's connection. On a short-lived Artisan process that is
     * invisible; under Octane, a queue worker or a test suite the connection outlives the
     * run, and unrelated queries then fail for a reason the application never chose — the
     * exact harm {@see self::snapshot()} exists to prevent.
     *
     * @param  array<string, string>  $snapshot
     */
    #[RawSql(reason: 'restores exactly the settings this guard changed, with the same SET verb the query builder cannot express')]
    public function restore(Connection $connection, array $snapshot): void
    {
        foreach ($snapshot as $setting => $value) {
            try {
                $connection->statement($this->restoreStatement($connection->getDriverName(), $setting, $value));
            } catch (Throwable) {
                // Nothing to report and nothing to fix — see above.
            }
        }
    }

    /**
     * One restore statement, in the literal form the engine accepts.
     *
     * The two engines want opposite things and neither tolerates the other's form:
     *
     * - PostgreSQL reports these settings WITH A UNIT (`5s`, `250ms`) and rejects the bare
     *   form on the way back, so the value has to be quoted.
     * - MySQL reports plain integers and rejects a quoted one for a numeric variable.
     *
     * A non-numeric value on MySQL is quoted anyway rather than interpolated raw: none of
     * the settings this guard touches produces one, and the day one does, a quoted literal
     * is a value the server will reject — not a fragment it will execute.
     *
     * ## The quote is doubled, not backslash-escaped
     *
     * `addslashes()` is the wrong escaper for one of the two engines this serves — and this method
     * serves both, so "one of the two" means every PostgreSQL restore.
     *
     * With `standard_conforming_strings` on, the default since 9.1, a backslash inside `'…'` is an
     * ordinary character on PostgreSQL. Measured on 18.0: `SELECT 'a\''` answers `ERROR: unterminated
     * quoted string`, because the `\'` ends the literal rather than escaping the quote, and the
     * trailing quote opens a new one. So `addslashes()` does not merely fail to protect — it converts
     * a value carrying a quote into a syntax error at best.
     *
     * Doubling is correct on both. Measured on MySQL 8.4.10, `SELECT 'a''b', 'a\'b'` returns `a'b`
     * twice: MySQL accepts either form, PostgreSQL only this one. So there is one idiom for both
     * engines rather than one per engine, which is what {@see PgsqlSessionDefense} and
     * {@see BindingSubstitutor} do as well.
     *
     * The values this method actually sees are validated GUC readbacks, so nothing here is
     * exploitable either way. The point is the idiom: two escaping forms for one job in one package
     * is one too many, and the next reader copies whichever they find first.
     */
    private function restoreStatement(string $driver, string $setting, string $value): string
    {
        return $driver === 'mysql' && is_numeric($value)
            ? sprintf('SET SESSION %s = %d', $setting, (int) $value)
            : sprintf("SET SESSION %s = '%s'", $setting, str_replace("'", "''", $value));
    }

    /** One session value as a string, or the empty string when the server will not say. */
    #[RawSql(reason: 'reads one server setting back; a session variable is not a column, so no builder can name it')]
    private function currentSetting(Connection $connection, string $query): string
    {
        // The write side, for the reason backendPid() gives: restore() puts this value back there,
        // so a value read from a replica would set the primary to the replica's bound.
        try {
            $row = $connection->selectOne($query, [], false);
        } catch (Throwable) {
            return '';
        }

        $value = is_object($row) ? array_values(get_object_vars($row))[0] ?? null : null;

        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * The session statements for an engine.
     *
     * PostgreSQL takes both budgets in milliseconds directly. MySQL does not:
     * `max_execution_time` is milliseconds but `innodb_lock_wait_timeout` is
     * SECONDS with a minimum of 1 — so a sub-second lock budget rounds UP to one
     * second rather than down to zero, because zero there means "fail
     * immediately", a different behavior than the short wait that was asked for.
     *
     * MySQL splits the lock budget in two, and both halves get it: `innodb_lock_wait_timeout`
     * bounds a wait on a ROW lock, `lock_wait_timeout` a wait on a METADATA lock, the one a
     * schema change queues behind. What MySQL cannot bound is the RUN of a schema change:
     * `max_execution_time` applies to read-only `SELECT` statements and to nothing else.
     *
     * @return list<string>
     */
    public function statementsFor(string $driver): array
    {
        return match ($driver) {
            'pgsql' => [
                sprintf('SET statement_timeout = %d', $this->budget['statement_timeout']),
                sprintf('SET lock_timeout = %d', $this->budget['lock_timeout']),
            ],
            'mysql' => [
                sprintf('SET SESSION max_execution_time = %d', $this->budget['statement_timeout']),
                sprintf('SET SESSION innodb_lock_wait_timeout = %d', $this->lockSeconds()),
                // The METADATA lock, which is the one DDL queues behind and the one
                // `innodb_lock_wait_timeout` does not reach: its default is a year. Same budget,
                // same seconds.
                sprintf('SET SESSION lock_wait_timeout = %d', $this->lockSeconds()),
            ],
            default => [],
        };
    }

    /**
     * The transaction-local statements for an engine: the same two PostgreSQL budgets as
     * {@see self::statementsFor()}, written `SET LOCAL` so they end with the transaction that
     * {@see self::within()} opens.
     *
     * Empty for every other engine. MySQL has no transaction-scoped form of its session variables,
     * which is why its bound stays a session one there, snapshotted and restored.
     *
     * @return list<string>
     */
    public function transactionStatementsFor(string $driver): array
    {
        return match ($driver) {
            'pgsql' => [
                sprintf('SET LOCAL statement_timeout = %d', $this->budget['statement_timeout']),
                sprintf('SET LOCAL lock_timeout = %d', $this->budget['lock_timeout']),
            ],
            default => [],
        };
    }

    /** The lock budget in whole seconds, never rounded down to "fail immediately". */
    private function lockSeconds(): int
    {
        return max(1, (int) ceil($this->budget['lock_timeout'] / 1000));
    }
}
