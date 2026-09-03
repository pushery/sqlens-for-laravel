<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Catalog;

use Pushery\SQLens\Catalog\SessionBudget;
use Pushery\SQLens\Contracts\SessionDefense;

/**
 * MySQL's half of the reader's self-restraint — and it is not PostgreSQL's, in three measured ways.
 *
 * 1. **The session-wide seal works here.** `SET SESSION transaction_read_only = ON` refused both DML
 *    and DDL with `SQLSTATE 25006` while leaving reads untouched. That is the simpler, stronger
 *    shape, and MySQL is the engine that offers it.
 * 2. **`SET TRANSACTION` is refused inside an open transaction** (`SQLSTATE 25001`, "transaction
 *    characteristics can't be changed"). So anything of that form has to be issued BEFORE the read
 *    transaction opens — which is why the interface has a slot for it at all.
 * 3. **`SET LOCAL` is not MySQL's spelling.** The bounds are session-scoped here; there is no
 *    transaction-scoped variant to fall back on.
 *
 * There is also no counterpart to PostgreSQL's `idle_in_transaction_session_timeout`. The nearest
 * relative, `wait_timeout`, bounds an idle CONNECTION rather than an idle transaction, and setting
 * it would look like the same protection while being a different one. It is left alone: an absent
 * guard that is named beats one that is claimed.
 */
final readonly class MysqlSessionDefense implements SessionDefense
{
    /** Refused because the transaction is read-only. */
    private const string READ_ONLY_SQL_STATE = '25006';

    /** The statement hit `max_execution_time` and was killed. */
    private const string QUERY_INTERRUPTED_SQL_STATE = '70100';

    /** The lock wait hit `innodb_lock_wait_timeout`. */
    private const string LOCK_WAIT_SQL_STATE = 'HY000';

    public function sessionStatements(SessionBudget $budget): array
    {
        return [
            sprintf('SET SESSION max_execution_time = %d', $budget->statementTimeoutMs),
            // MySQL takes this one in SECONDS, not milliseconds, and rounds up to at least one:
            // a sub-second budget expressed as `0` would mean "wait forever", the value this whole
            // type refuses.
            sprintf('SET SESSION innodb_lock_wait_timeout = %d', max(1, (int) ceil($budget->lockTimeoutMs / 1000))),
        ];
    }

    /**
     * The seal, and it goes here because MySQL refuses to take it once a transaction is open.
     *
     * Session scope rather than the next transaction only: a reader that opened a second
     * transaction would otherwise be unsealed for it, and the promise would hold for exactly as
     * long as nobody extended the code.
     */
    public function preTransactionStatements(): array
    {
        return ['SET SESSION transaction_read_only = ON'];
    }

    /** Nothing: the seal is already on the session and MySQL has no `SET LOCAL`. */
    public function inTransactionStatements(SessionBudget $budget): array
    {
        return [];
    }

    /** A write that creates nothing and touches no user data — it only has to BE a write. */
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

     * MySQL answers a denied write with 42000 — the same class it uses for syntax errors, which
     * is why the seal has to ask this as its own question rather than pattern-match a message.
     */
    public function isPrivilegeRefusal(string $sqlState): bool
    {
        return $sqlState === '42000';
    }

    public function isTimeout(string $sqlState): bool
    {
        return $sqlState === self::QUERY_INTERRUPTED_SQL_STATE || $sqlState === self::LOCK_WAIT_SQL_STATE;
    }
}
