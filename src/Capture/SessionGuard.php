<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Illuminate\Database\Connection;
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
 * Session scope only. The tool never changes a global, and it never takes a lock
 * of its own; it only limits how long IT is willing to wait.
 *
 * The statements are per-engine, but the class stays driver-neutral: it switches
 * on the connection's driver KEY, never on a driver class, so the capture
 * namespace keeps importing nothing from `Drivers\Pgsql` or `Drivers\Mysql`.
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
 *     setting written here is one {@see self::snapshot()} must read and {@see self::restore()}
 *     must put back — and two of them are not merely inconvenient to restore, they are harmful to
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
 * The row is gone and the connection with it. And the setting could never have helped: SQLens
 * opens no transaction on this connection — the only `beginTransaction` in `src/` is the reader
 * session's — so the session it guards cannot sit idle in one of SQLens's own making. A bound with
 * no upside and a measured downside is not a gap.
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
            ],
            default => [],
        };
    }

    /**
     * Put a snapshot back. A restore that cannot run is swallowed deliberately: the run
     * is over and its result already stands, so throwing here would turn a completed lint
     * into a crash over housekeeping. The connection dying is itself the restore.
     *
     * ⚠️ That swallow is why the LITERAL FORM below has to be right per engine rather than
     * merely plausible. Measured on MySQL 8.4: `SET SESSION max_execution_time = '0'` is
     * refused with error 1232, "Incorrect argument type to variable" — MySQL takes the bare
     * numeric form for a numeric system variable, and the quoted one is a type error. The
     * swallow then made a total failure to restore look exactly like a successful one, and
     * every lint run left `max_execution_time = 5000` and `innodb_lock_wait_timeout = 3`
     * behind on the HOST APPLICATION's connection. On a short-lived Artisan process that is
     * invisible; under Octane, a queue worker or a test suite the connection outlives the
     * run, and unrelated queries then fail for a reason the application never chose — the
     * exact harm {@see self::snapshot()} exists to prevent, on the engine nobody measured.
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
     */
    private function restoreStatement(string $driver, string $setting, string $value): string
    {
        return $driver === 'mysql' && is_numeric($value)
            ? sprintf('SET SESSION %s = %d', $setting, (int) $value)
            : sprintf("SET SESSION %s = '%s'", $setting, addslashes($value));
    }

    /** One session value as a string, or the empty string when the server will not say. */
    #[RawSql(reason: 'reads one server setting back; a session variable is not a column, so no builder can name it')]
    private function currentSetting(Connection $connection, string $query): string
    {
        try {
            $row = $connection->selectOne($query);
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
