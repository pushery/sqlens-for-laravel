<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Catalog;

use Pushery\SQLens\Capture\Shadow\SessionTimeoutDetector;
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

    /**
     * The privileges that only read. A grant naming any other is not read as proof that the account
     * cannot write: the list says what is known to be harmless, never what is known to be harmful.
     * `EXECUTE` is left out on purpose, because a `SQL SECURITY DEFINER` routine writes with its
     * definer's rights.
     */
    private const array READING_PRIVILEGES = [
        'SELECT', 'USAGE', 'SHOW VIEW', 'SHOW DATABASES', 'PROCESS', 'REPLICATION CLIENT', 'SHOW_ROUTINE',
    ];

    public function sessionStatements(SessionBudget $budget): array
    {
        return [
            sprintf('SET SESSION max_execution_time = %d', $budget->statementTimeoutMs),
            // MySQL takes this one in SECONDS, not milliseconds, and rounds up to at least one:
            // a sub-second budget expressed as `0` would mean "wait forever", the value this whole
            // type refuses.
            sprintf('SET SESSION innodb_lock_wait_timeout = %d', max(1, (int) ceil($budget->lockTimeoutMs / 1000))),
            // The metadata lock, which a catalog read takes too and which `innodb_lock_wait_timeout`
            // does not reach: its default is a year, so a reader queued behind a pending schema change
            // would wait that long. Same seconds, same floor.
            sprintf('SET SESSION lock_wait_timeout = %d', max(1, (int) ceil($budget->lockTimeoutMs / 1000))),
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
     * Whether a privilege refused the probe.
     *
     * MySQL answers a denied write with 42000 — the same class it uses for syntax errors, which
     * is why the seal has to ask this as its own question rather than pattern-match a message. It
     * asks the grant before the read-only flag, so the answer covers every account without the
     * right to create a temporary table, whatever else it may do.
     */
    public function isPrivilegeRefusal(string $sqlState): bool
    {
        return $sqlState === '42000';
    }

    /**
     * The session value, which the transaction took when it opened: the seal is set on the session
     * before the transaction starts, and nothing between the two changes it.
     */
    public function readOnlyFlagQuery(): string
    {
        return 'SELECT @@SESSION.transaction_read_only';
    }

    public function flagMeansReadOnly(string $value): bool
    {
        return $value === '1';
    }

    /**
     * The account's own grants. MySQL merges the privileges of the roles active in the session into
     * the listing and names every granted role on a line of its own, active or not.
     */
    public function grantListingQuery(): string
    {
        return 'SHOW GRANTS FOR CURRENT_USER()';
    }

    public function grantsForbidWriting(array $lines): bool
    {
        if ($lines === []) {
            return false;
        }

        foreach ($lines as $line) {
            // A partial revoke only narrows a grant, so it cannot be what lets an account write.
            if (strncasecmp($line, 'REVOKE ', 7) === 0) {
                continue;
            }

            $skips = [];
            $grants = MysqlGrantLine::read([$line], $skips);

            // A role membership, a line that did not parse, anything that is not a privilege grant:
            // it could carry a write, and a line this reading cannot vouch for is not a proof. A
            // granted role counts even when it is not active, because the session could activate it.
            if ($grants === []) {
                return false;
            }

            foreach ($grants as $grant) {
                if ($grant->grantable) {
                    return false;
                }

                foreach ($grant->privileges as $privilege) {
                    // A column list says where a privilege applies, not what it allows.
                    $name = strtoupper(trim((string) preg_replace('/\s*\(.*$/s', '', $privilege)));

                    if (! in_array($name, self::READING_PRIVILEGES, true)) {
                        return false;
                    }
                }
            }
        }

        return true;
    }

    public function isTimeout(string $sqlState, ?int $driverCode): bool
    {
        // Through the ONE classifier. Both engines' answers used to live here, and both were
        // wrong in opposite directions — see SessionDefense::isTimeout().
        return SessionTimeoutDetector::matchesTimeout($sqlState, $driverCode);
    }
}
