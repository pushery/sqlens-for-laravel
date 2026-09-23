<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Catalog;

use Pdo\Pgsql as PdoPgsql;
use Pushery\SQLens\Capture\Shadow\SessionTimeoutDetector;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Catalog\SessionBudget;
use Pushery\SQLens\Contracts\SessionDefense;

/**
 * PostgreSQL's half of the reader's self-restraint.
 *
 * ## Why the seal is a TRANSACTION and not a session setting
 *
 * Measured against a real PostgreSQL 18 through Laravel's connection API: an explicit transaction
 * marked `READ ONLY` refused a write every time, with `SQLSTATE 25006`. The session-wide
 * `default_transaction_read_only` — which refuses correctly in `psql` — did not, and rows really
 * landed. The mechanism behind that divergence was not established, so nothing is claimed about it;
 * what is used is the shape that held in every probe.
 *
 * That is also why the reader verifies the seal instead of trusting it. See
 * {@see ReaderSession}.
 *
 * ## Why every bound is `SET LOCAL` and nothing is set at session scope
 *
 * `SET LOCAL` ends with the transaction, which is the one scope a transaction pooler guarantees. A
 * plain session `SET` does not: behind PgBouncer in transaction pooling it lands on whichever
 * backend carried that statement and STAYS there. `server_reset_query` runs only in session pooling
 * by default, and `track_extra_parameters` can only reset parameters the server announces through
 * `ParameterStatus` — which none of the three timeouts are. The next session of the HOST
 * APPLICATION that is handed that backend inherits them and starts losing queries over the budget
 * to `57014` and idle transactions to a FATAL `25P03`, for a reason it never chose. The reader
 * connection is a copy of the application's config, so it goes through the same pooler.
 *
 * The bounds are set once, as `SET LOCAL`, and not also on the session as a second safeguard. That
 * copy would be the leak described above, and it would buy nothing: everything this session does
 * happens inside the read transaction, so there is no window a session-scoped copy would cover and
 * no topology in which it earns its risk.
 *
 * `idle_in_transaction_session_timeout` is the one with no MySQL counterpart and it matters most
 * here: a read transaction that stalls holds a snapshot open, and an open snapshot stops `VACUUM`
 * from reclaiming anything on the whole database. A reader that hung would not merely be slow, it
 * would be actively harmful.
 *
 * ## Why the reader's connection prepares no NAMED statements
 *
 * PDO prepares each query as a named server-side statement and, when the statement object goes
 * away, may remove it again with a plain `DEALLOCATE pdo_stmt_…`. Behind PgBouncer in transaction
 * pooling with `max_prepared_statements`, the server never saw that name: the pooler renamed the
 * statement when it forwarded it, and a plain `DEALLOCATE` is not renamed. The server answers
 * `26000`, and because the reader always reads inside a transaction, that error aborts it. The next
 * statement then fails with `25P02`, at a place that has nothing to do with the cause.
 *
 * So the reader's own copy of the connection is opened with {@see self::readerConnectionOptions()}.
 * Each query and its parameters travel in one unnamed round trip, the parameters are still bound by
 * the server, and there is nothing left to deallocate. A reader reuses no statement, so nothing is
 * lost, and the application's own connection keeps whatever it configured.
 */
final readonly class PgsqlSessionDefense implements SessionDefense
{
    /** Refused because the transaction is read-only. */
    private const string READ_ONLY_SQL_STATE = '25006';

    /**
     * The PDO attributes the reader's own copy of a PostgreSQL connection is opened with.
     *
     * Empty without `pdo_pgsql`: such a host cannot open a PostgreSQL connection at all, and naming
     * the attribute's class there would fail before any connection is attempted.
     *
     * @return array<int, mixed>
     */
    public static function readerConnectionOptions(): array
    {
        return extension_loaded('pdo_pgsql') ? [PdoPgsql::ATTR_DISABLE_PREPARES => true] : [];
    }

    /** Nothing. Everything this session sets is scoped to its transaction — see the note above. */
    public function sessionStatements(SessionBudget $budget): array
    {
        return [];
    }

    /** Nothing: PostgreSQL takes its seal inside the transaction, not before it. */
    public function preTransactionStatements(): array
    {
        return [];
    }

    public function inTransactionStatements(SessionBudget $budget): array
    {
        return [
            'SET TRANSACTION READ ONLY',
            sprintf("SET LOCAL statement_timeout = '%dms'", $budget->statementTimeoutMs),
            sprintf("SET LOCAL lock_timeout = '%dms'", $budget->lockTimeoutMs),
            sprintf("SET LOCAL idle_in_transaction_session_timeout = '%dms'", $budget->idleInTransactionTimeoutMs),
            // Quoted by doubling, the way PostgreSQL takes a literal apostrophe. An unescaped name
            // would not merely mislabel the session — it would end the statement early.
            sprintf("SET LOCAL application_name = '%s'", str_replace("'", "''", $budget->applicationName)),
        ];
    }

    /**
     * A write that touches no user table and creates nothing — it only has to be a WRITE, so a
     * read-only transaction refuses it. A probe that needed a table of its own would be a reader
     * that creates things, which is the opposite of the promise it is proving.
     */
    public function writeProbe(): string
    {
        return 'CREATE TEMPORARY TABLE sqlens_read_only_probe (id int)';
    }

    public function isReadOnlyRefusal(string $sqlState): bool
    {
        return $sqlState === self::READ_ONLY_SQL_STATE;
    }

    /**
     * Whether the account simply may not write.
     *
     * PostgreSQL answers a denied write with 42501, insufficient_privilege — distinct from the
     * 25006 a read-only transaction gives, and every bit as conclusive about what cannot happen.
     */
    public function isPrivilegeRefusal(string $sqlState): bool
    {
        return $sqlState === '42501';
    }

    public function isTimeout(string $sqlState, ?int $driverCode): bool
    {
        // Through the ONE classifier. Both engines' answers used to live here, and both were
        // wrong in opposite directions — see SessionDefense::isTimeout().
        return SessionTimeoutDetector::matchesTimeout($sqlState, $driverCode);
    }
}
