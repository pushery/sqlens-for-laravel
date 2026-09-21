<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L3\Support;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Canonical\StringLiteralMask;
use Pushery\SQLens\Drivers\Pgsql\Canonical\PgsqlCanonicalization;
use Pushery\SQLens\Subjects\MigrationContext;
use Pushery\SQLens\Subjects\MigrationStatementDigest;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Which statements take a lock strong enough to matter — the shared PostgreSQL reading
 * the three level-3 timeout/transaction rules all build on, so it is defined ONCE here
 * and not re-derived (subtly differently) in each.
 *
 * A "strong lock" here is one that blocks concurrent access and must WAIT in the lock
 * queue to be taken: `ALTER TABLE` in its forms (ACCESS EXCLUSIVE), a non-concurrent
 * `CREATE INDEX`/`DROP INDEX`, `TRUNCATE`, and `DROP TABLE`. It is the class of
 * operation that a `lock_timeout` bounds and that, un-bounded, can pile every later
 * query up behind it — and the class `MISSING_LOCK_TIMEOUT`, `MISSING_STATEMENT_TIMEOUT`
 * and `RISKY_OPS_SINGLE_TX` all reason about.
 *
 * Two operations are deliberately NOT strong locks here. `CREATE TABLE` builds a new
 * object nobody is waiting on. A bare `RENAME` (`ALTER TABLE … RENAME`) takes ACCESS
 * EXCLUSIVE but only for a metadata flip that is effectively instant — flagging every
 * `renameColumn()` migration for a missing timeout is the cry-wolf noise a linter gets
 * switched off for, so it is left out and this boundary is stated where it is drawn.
 *
 * The reading is on the CANONICAL form and the driver-neutral classification, never raw
 * grammar. `CONCURRENTLY` is a PostgreSQL clause and lives here behind the driver
 * boundary, where engine vocabulary belongs.
 */
final class StrongLockStatements
{
    /**
     * Whether the statement takes a strong, queue-waiting lock. The index kinds are
     * strong only when NOT concurrent — the whole point of `CONCURRENTLY` is to trade a
     * strong lock for a slow, online build.
     */
    public static function takesStrongLock(MigrationStatementDigest $digest): bool
    {
        return match ($digest->kind) {
            StatementKind::AlterTable,
            // `ALTER TABLE … ADD COLUMN` takes ACCESS EXCLUSIVE like every other form of it. Listed
            // explicitly so the answer does not depend on whether the grammar happens to give the
            // statement its own kind — which is exactly the dependency that made the two rules above
            // go quiet on MySQL.
            StatementKind::AddColumn,
            StatementKind::AddConstraint,
            StatementKind::DropConstraint,
            StatementKind::DropColumn,
            StatementKind::DropTable,
            StatementKind::TruncateTable => true,
            StatementKind::CreateIndex,
            StatementKind::DropIndex => ! self::isConcurrent($digest->canonical),
            default => false,
        };
    }

    /**
     * The first strong-lock statement in the stream that acts on an object this
     * migration did NOT create — the point at which a timeout should already be in
     * effect. A strong lock on a table the same migration just created contends with no
     * one (the table is invisible outside the transaction until commit), so it is
     * skipped, exactly as the blocking-DDL rules skip a same-migration table. A
     * statement whose table cannot be resolved (a `DROP INDEX` names the index, not the
     * table) is kept: better to ask for a timeout than to miss one on an unprovable case.
     *
     * Returns null when the migration takes no such lock — a pure `CREATE TABLE`
     * migration, or one that only touches tables it itself created, needs no timeout.
     *
     * @param  list<MigrationStatementDigest>  $stream
     */
    public static function firstGateStatement(array $stream, MigrationContext $migration): ?MigrationStatementDigest
    {
        foreach ($stream as $digest) {
            if (! self::takesStrongLock($digest)) {
                continue;
            }

            if (self::locksOnlyFreshTables($digest, $migration)) {
                continue;
            }

            return $digest;
        }

        return null;
    }

    /**
     * Whether every table this statement locks was created in the same migration — the
     * carve-out scaled to a statement that touches MORE than one table. A foreign key
     * `ADD CONSTRAINT` names both the constrained AND the referenced table, so a single
     * `soleTarget` cannot see it; a pivot migration that creates both tables and then wires
     * the key would otherwise be flagged, which is the commonest migration shape there is.
     * A statement with no resolvable table (a `DROP INDEX` names the index) is NOT fresh —
     * it is kept, conservatively, exactly as before.
     */
    private static function locksOnlyFreshTables(MigrationStatementDigest $digest, MigrationContext $migration): bool
    {
        $tables = array_values(array_filter(
            $digest->targets,
            static fn (StatementTarget $target): bool => $target->type === SchemaObjectType::Table,
        ));

        if ($tables === []) {
            return false;
        }

        return array_all($tables, static fn (StatementTarget $target): bool => $migration->createsTable($target->qualifiedName()));
    }

    /**
     * Whether the stream sets the named timeout at any point BEFORE the given gate
     * index. Order is the whole question: a `SET lock_timeout` AFTER the risky DDL does
     * not protect it, so only statements ahead of the gate count.
     *
     * @param  list<MigrationStatementDigest>  $stream
     */
    public static function timeoutSetBefore(array $stream, int $gateIndex, string $timeout): bool
    {
        return array_any(
            $stream,
            static fn (MigrationStatementDigest $digest): bool => $digest->index < $gateIndex && self::setsTimeout($digest, $timeout),
        );
    }

    /**
     * The strong-lock statements that run WITHIN a transaction on a pre-existing table
     * whose identity resolves — the locks that all pile up until the one commit, and that
     * can be attributed to a named table. In stream order.
     *
     * Statements outside a transaction do not accumulate (each commits on its own), a lock
     * on a table the migration itself just created contends with no one, and a lock whose
     * table cannot be named (a `DROP INDEX` names the index) is left out rather than
     * counted as an unnamed extra table. This is the input the bundled-operations rule
     * counts distinct tables over.
     *
     * @param  list<MigrationStatementDigest>  $stream
     * @return list<MigrationStatementDigest>
     */
    public static function resolvableTransactionLocks(array $stream, MigrationContext $migration): array
    {
        return array_values(array_filter($stream, static function (MigrationStatementDigest $digest) use ($migration): bool {
            if (! $digest->withinTransaction || ! self::takesStrongLock($digest)) {
                return false;
            }

            // The SUBJECT table, not the sole one. A `FOREIGN KEY … REFERENCES` names two tables,
            // so `soleTarget()` answers null and the statement fell out of this list — although
            // `takesStrongLock()` lists AddConstraint and the statement really does take an ACCESS
            // EXCLUSIVE lock. A migration whose only strong-lock statement was a foreign key was
            // therefore read as one with no resolvable locks at all.
            $table = $digest->soleSubjectTarget(SchemaObjectType::Table);

            return $table instanceof StatementTarget && ! $migration->createsTable($table->qualifiedName());
        }));
    }

    /**
     * Whether the statement EFFECTIVELY sets the named GUC — how a migration declares its own
     * timeout. Read off the canonical string because a plain `SET` is not a classified DDL kind.
     *
     * ⚠️ **`SET LOCAL` only counts inside a transaction, and that is not a nicety.** The manual is
     * explicit: *"SET LOCAL will appear to have no effect if it is executed outside a BEGIN block,
     * since the transaction will end immediately."* Measured on PostgreSQL 18.0 — `SET LOCAL
     * lock_timeout = '3s'` in autocommit answers `WARNING: SET LOCAL can only be used in transaction
     * blocks` and leaves `lock_timeout` at `0`, while a plain `SET` leaves it at `3s`.
     *
     * So a migration declaring `public $withinTransaction = false` — which every `CONCURRENTLY`
     * migration must, and which this package's own remediation tells it to — ran its risky DDL with
     * NO bound while this predicate reported one. A false green on a rule that exists to find an
     * unbounded wait, and the most expensive shape of it: the operator has written the line, can see
     * the line, and believes the wait is capped.
     *
     * The literals are masked first for the same reason the MySQL side masks them: an `->insert()`
     * whose value spells `set lock_timeout = 5s` is data, and counting it would be the same false
     * green arriving through the other door.
     */
    public static function setsTimeout(MigrationStatementDigest $digest, string $timeout): bool
    {
        $canonical = StringLiteralMask::forDriver(new PgsqlCanonicalization)->apply($digest->canonical);

        if (preg_match('/\bSET\s+(SESSION\s+|LOCAL\s+)?'.preg_quote($timeout, '/').'\b/i', $canonical, $match) !== 1) {
            return false;
        }

        return ! self::isLocalScope($match[1] ?? '') || $digest->withinTransaction;
    }

    /**
     * Whether the stream declares the named timeout with `SET LOCAL` somewhere before the gate while
     * running outside a transaction — the shape that reads as a bound and is none.
     *
     * It exists so the finding can say WHICH mistake was made. Without it the rule tells an operator
     * that no timeout was set, while the operator is looking at the line that sets it, and the most
     * likely conclusion is that the tool is wrong.
     *
     * @param  list<MigrationStatementDigest>  $stream
     */
    public static function ineffectiveLocalTimeoutBefore(array $stream, int $gateIndex, string $timeout): bool
    {
        $mask = StringLiteralMask::forDriver(new PgsqlCanonicalization);

        return array_any($stream, static function (MigrationStatementDigest $digest) use ($gateIndex, $timeout, $mask): bool {
            if ($digest->index >= $gateIndex || $digest->withinTransaction) {
                return false;
            }

            $matched = preg_match(
                '/\bSET\s+(SESSION\s+|LOCAL\s+)?'.preg_quote($timeout, '/').'\b/i',
                $mask->apply($digest->canonical),
                $match,
            );

            return $matched === 1 && self::isLocalScope($match[1] ?? '');
        });
    }

    /** Whether the captured scope word is `LOCAL`. An absent scope is session scope, which is effective. */
    private static function isLocalScope(string $scope): bool
    {
        return stripos($scope, 'LOCAL') !== false;
    }

    /** Whether the canonical form carries the `CONCURRENTLY` clause. */
    private static function isConcurrent(string $canonical): bool
    {
        return preg_match('/\bCONCURRENTLY\b/', $canonical) === 1;
    }
}
