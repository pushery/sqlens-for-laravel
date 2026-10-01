<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L3\Support;

use Pushery\SQLens\Canonical\CanonicalName;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Canonical\StringLiteralMask;
use Pushery\SQLens\Drivers\Pgsql\Canonical\PgsqlCanonicalization;
use Pushery\SQLens\Drivers\Pgsql\Rules\Support\ShareUpdateExclusiveAlter;
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
 * Three operations are deliberately NOT strong locks here. `CREATE TABLE` builds a new
 * object nobody is waiting on. A bare `RENAME` (`ALTER TABLE … RENAME`) takes ACCESS
 * EXCLUSIVE but only for a metadata flip that is effectively instant — flagging every
 * `renameColumn()` migration for a missing timeout is the cry-wolf noise a linter gets
 * switched off for, so it is left out and this boundary is stated where it is drawn. And
 * `ALTER TABLE … VALIDATE CONSTRAINT`, like a change of a maintenance storage parameter such
 * as `fillfactor`, takes SHARE UPDATE EXCLUSIVE, which no read and no write waits behind:
 * validating is the second step after `NOT VALID`, and flagging it would flag the migration
 * that follows the advice ({@see ShareUpdateExclusiveAlter}).
 *
 * A statement the classifier gives no kind of its own (`ddl_other`) is read from its form, not
 * waved through: a trigger, a policy, a rule, a view that exists, a sequence and most forms of
 * `ALTER INDEX` take locks that block reads or writes, measured one by one
 * ({@see self::otherDdlTakesStrongLock()}). A `DROP SCHEMA` counts when it cascades, because
 * it then drops every table in the schema along with its lock.
 *
 * The reading is on the CANONICAL form and the driver-neutral classification, never raw
 * grammar. `CONCURRENTLY` is a PostgreSQL clause and lives here behind the driver
 * boundary, where engine vocabulary belongs.
 */
final class StrongLockStatements
{
    /** Every name the canonical form can write, quoted or not. */
    private const string NAME = '(?:'.CanonicalName::PATTERN.')';

    /** The `ddl_other` forms that take a lock blocking reads or writes (see {@see self::otherDdlTakesStrongLock()}). */
    private const string STRONG_OTHER_DDL = '/^(?:'
        .'ALTER INDEX (?:IF EXISTS )?(?:ALL IN TABLESPACE\b|'.self::NAME.'(?:\.'.self::NAME.')? (?!RENAME\b|SET\s*\(|RESET\s*\(|ALTER\s+(?:COLUMN\b|\d)))'
        .'|CREATE (?:OR REPLACE )?(?:CONSTRAINT )?TRIGGER\b'
        .'|(?:ALTER|DROP) TRIGGER\b'
        .'|(?:CREATE|ALTER|DROP) POLICY\b'
        .'|(?:CREATE (?:OR REPLACE )?|ALTER |DROP )RULE\b'
        .'|CREATE OR REPLACE (?:(?:TEMP|TEMPORARY|RECURSIVE) )*VIEW\b'
        .'|(?:ALTER|DROP) (?:MATERIALIZED )?VIEW\b'
        .'|(?:ALTER|DROP) SEQUENCE\b'
        .'|DROP\b.*\bCASCADE\b'
        .')/is';

    /** A trigger, policy or rule statement, the forms that name their table only in their text. */
    private const string TRIGGER_POLICY_OR_RULE = '/^(?:CREATE (?:OR REPLACE )?(?:CONSTRAINT )?TRIGGER|(?:ALTER|DROP) TRIGGER|(?:CREATE|ALTER|DROP) POLICY|(?:CREATE (?:OR REPLACE )?|ALTER |DROP )RULE)\b/i';

    /**
     * Whether the statement takes a strong, queue-waiting lock. The index kinds are
     * strong only when NOT concurrent — the whole point of `CONCURRENTLY` is to trade a
     * strong lock for a slow, online build.
     */
    public static function takesStrongLock(MigrationStatementDigest $digest): bool
    {
        return match ($digest->kind) {
            StatementKind::AlterTable => ! ShareUpdateExclusiveAlter::only($digest->kind, $digest->canonical),
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
            StatementKind::DropSchema => self::cascades($digest->canonical),
            StatementKind::DdlOther => self::otherDdlTakesStrongLock($digest->canonical),
            default => false,
        };
    }

    /**
     * Whether a statement the classifier leaves as `ddl_other` takes a lock that blocks the reads or
     * the writes of a relation that already exists. Each form below was measured on PostgreSQL 18.4,
     * with the lock read from `pg_locks` inside the statement's own transaction:
     *
     * | Form | Lock it holds |
     * |---|---|
     * | `ALTER INDEX` other than `RENAME`, `SET (…)`, `RESET (…)`, `ALTER COLUMN` | ACCESS EXCLUSIVE on the index (`SET TABLESPACE`) |
     * | `CREATE TRIGGER` | SHARE ROW EXCLUSIVE on the table |
     * | `ALTER TRIGGER`, `DROP TRIGGER` | ACCESS EXCLUSIVE on the table |
     * | `CREATE`, `ALTER`, `DROP POLICY` | ACCESS EXCLUSIVE on the table |
     * | `CREATE RULE` | ACCESS EXCLUSIVE on the table |
     * | `CREATE OR REPLACE VIEW`, `ALTER VIEW`, `DROP VIEW` | ACCESS EXCLUSIVE on the view |
     * | `ALTER`, `DROP MATERIALIZED VIEW` | ACCESS EXCLUSIVE on the view |
     * | `ALTER SEQUENCE`, `DROP SEQUENCE` | SHARE ROW EXCLUSIVE, ACCESS EXCLUSIVE on the sequence |
     * | any other `DROP … CASCADE` | ACCESS EXCLUSIVE on what it reaches: a function's trigger locks its table |
     *
     * The `ALTER INDEX` forms follow the manual's rule for them, ACCESS EXCLUSIVE unless a form says
     * otherwise, and `ALTER` and `DROP RULE` are read like `CREATE RULE`.
     *
     * Measured as not strong, and read that way: `ALTER INDEX … RENAME`, `ALTER INDEX … SET (…)` and
     * `COMMENT ON` (SHARE UPDATE EXCLUSIVE); `GRANT` and `REVOKE` (ACCESS SHARE); `CREATE VIEW` and
     * `CREATE MATERIALIZED VIEW` (ACCESS SHARE on what they read); `CREATE SEQUENCE`, `CREATE FUNCTION`,
     * `CREATE EXTENSION`, `ALTER FUNCTION … RENAME`, `ALTER TYPE … ADD VALUE` or `RENAME VALUE`, and a
     * `DROP TYPE` without `CASCADE`, none of which locks an existing relation. A form on neither list
     * is read as not strong. That is where this reading ends, and a form found taking a strong lock
     * belongs in the table above.
     */
    private static function otherDdlTakesStrongLock(string $canonical): bool
    {
        return preg_match(self::STRONG_OTHER_DDL, StringLiteralMask::forDriver(new PgsqlCanonicalization)->apply($canonical)) === 1;
    }

    /** Whether a `DROP` cascades, which takes the objects it reaches along with their locks. */
    private static function cascades(string $canonical): bool
    {
        return preg_match('/\bCASCADE\b/i', StringLiteralMask::forDriver(new PgsqlCanonicalization)->apply($canonical)) === 1;
    }

    /**
     * The table a trigger, policy or rule statement names, read from its text because the classifier
     * gives these statements no target. Null for any other statement.
     */
    private static function tableNamedBy(MigrationStatementDigest $digest): ?string
    {
        if ($digest->kind !== StatementKind::DdlOther) {
            return null;
        }

        $canonical = StringLiteralMask::forDriver(new PgsqlCanonicalization)->apply($digest->canonical);

        // A rule names its event after ON and its table after TO; the others name the table after ON.
        $after = preg_match('/^CREATE (?:OR REPLACE )?RULE\b/i', $canonical) === 1 ? 'TO' : 'ON';

        if (preg_match(self::TRIGGER_POLICY_OR_RULE, $canonical) !== 1
            || preg_match('/\b'.$after.'\s+('.self::NAME.'(?:\.'.self::NAME.')?)/i', $canonical, $table) !== 1) {
            return null;
        }

        return $table[1];
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
            // A trigger, policy or rule names its table only in its text, and on a table the
            // migration just created it contends with no one either.
            $named = self::tableNamedBy($digest);

            return $named !== null && $migration->createsTable($named);
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
     * **`SET LOCAL` only counts inside a transaction, and that is not a nicety.** The manual is
     * explicit: *"SET LOCAL will appear to have no effect if it is executed outside a BEGIN block,
     * since the transaction will end immediately."* Measured on PostgreSQL 18.0 — `SET LOCAL
     * lock_timeout = '3s'` in autocommit answers `WARNING: SET LOCAL can only be used in transaction
     * blocks` and leaves `lock_timeout` at `0`, while a plain `SET` leaves it at `3s`.
     *
     * So in a migration declaring `public $withinTransaction = false` — which every `CONCURRENTLY`
     * migration must, and which this package's own remediation tells it to — a `SET LOCAL` bounds
     * nothing. Counting it would be a false green on a rule that exists to find an unbounded wait,
     * and the most expensive shape of it: the operator has written the line, can see the line, and
     * believes the wait is capped.
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
