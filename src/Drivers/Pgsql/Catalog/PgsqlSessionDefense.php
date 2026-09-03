<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Catalog;

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
 * ## Why the bounds are set twice
 *
 * Once on the session, once as `SET LOCAL` inside the read transaction. The duplication is
 * deliberate: `SET LOCAL` is scoped to the transaction, which is the property a transaction pooler
 * needs — a plain session `SET` may be handed to another client later. The session `SET` is the
 * belt to that brace, and costs one statement.
 *
 * `idle_in_transaction_session_timeout` is the one with no MySQL counterpart and it matters most
 * here: a read transaction that stalls holds a snapshot open, and an open snapshot stops `VACUUM`
 * from reclaiming anything on the whole database. A reader that hung would not merely be slow, it
 * would be actively harmful.
 */
final readonly class PgsqlSessionDefense implements SessionDefense
{
    /** Refused because the transaction is read-only. */
    private const string READ_ONLY_SQL_STATE = '25006';

    /** The statement (or the lock wait) hit its budget and was canceled. */
    private const string QUERY_CANCELED_SQL_STATE = '57014';

    public function sessionStatements(SessionBudget $budget): array
    {
        return [
            sprintf("SET statement_timeout = '%dms'", $budget->statementTimeoutMs),
            sprintf("SET lock_timeout = '%dms'", $budget->lockTimeoutMs),
            sprintf("SET idle_in_transaction_session_timeout = '%dms'", $budget->idleInTransactionTimeoutMs),
            sprintf("SET application_name = '%s'", str_replace("'", "''", $budget->applicationName)),
        ];
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

     * PostgreSQL answers a denied write with 42501, insufficient_privilege — distinct from the
     * 25006 a read-only transaction gives, and every bit as conclusive about what cannot happen.
     */
    public function isPrivilegeRefusal(string $sqlState): bool
    {
        return $sqlState === '42501';
    }

    public function isTimeout(string $sqlState): bool
    {
        return $sqlState === self::QUERY_CANCELED_SQL_STATE;
    }
}
