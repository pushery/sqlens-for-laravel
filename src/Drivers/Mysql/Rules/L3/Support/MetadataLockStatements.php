<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L3\Support;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Subjects\MigrationContext;
use Pushery\SQLens\Subjects\MigrationStatementDigest;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Which MySQL statements take a METADATA lock on a table that already existed.
 *
 * The PostgreSQL side has an equivalent and it is deliberately not imported: the statement kinds a
 * MySQL migration produces are a different set (it classifies `AddForeignKey`, `AddPrimaryKey`,
 * `CreateFulltextIndex` and `CreateSpatialIndex` as kinds of their own, none of which exists on the
 * other driver), and a shared list would drift toward whichever engine was edited last.
 *
 * ## Why "on a table that already existed" is half the definition
 *
 * A migration that creates a table and then indexes it takes a metadata lock on an object nobody
 * else can be holding — there is no queue to stall, because the object did not exist a statement
 * ago. Flagging it would make the rule fire on the most ordinary migration there is, and a rule
 * people mute takes its real cases with it.
 */
final readonly class MetadataLockStatements
{
    /**
     * The kinds that take a metadata lock strong enough to block readers and writers.
     *
     * `Dml`, `SessionSetting` and `CreateTable` are absent on purpose: the first takes row locks
     * (a different setting bounds those), the second is how the preamble itself is written, and the
     * third creates the object rather than queueing for it.
     */
    private const array LOCKING_KINDS = [
        StatementKind::AlterTable,
        StatementKind::AddColumn,
        StatementKind::AlterColumn,
        StatementKind::DropColumn,
        StatementKind::AddConstraint,
        StatementKind::DropConstraint,
        StatementKind::AddForeignKey,
        StatementKind::AddPrimaryKey,
        StatementKind::CreateIndex,
        StatementKind::CreateFulltextIndex,
        StatementKind::CreateSpatialIndex,
        StatementKind::DropIndex,
        StatementKind::DropTable,
        StatementKind::TruncateTable,
        StatementKind::Rename,
    ];

    /**
     * The first statement whose lock a preamble would have to bound, or null when there is none.
     *
     * @param  list<MigrationStatementDigest>  $stream
     */
    public static function firstGateStatement(array $stream, MigrationContext $migration): ?MigrationStatementDigest
    {
        foreach ($stream as $digest) {
            if (! self::takesMetadataLock($digest)) {
                continue;
            }
            if (self::locksOnlyFreshTables($digest, $migration)) {
                continue;
            }

            return $digest;
        }

        return null;
    }

    /** Whether this statement takes a metadata lock at all. */
    public static function takesMetadataLock(MigrationStatementDigest $digest): bool
    {
        return in_array($digest->kind, self::LOCKING_KINDS, true);
    }

    /**
     * Whether the named timeout was set anywhere BEFORE the gate.
     *
     * Anywhere, not immediately before: a preamble at the top of `up()` bounds every statement that
     * follows it in the session, and requiring adjacency would report a migration that is already
     * doing the right thing.
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
     * Whether the statement is a `SET [SESSION] <timeout> = …` for exactly the named variable.
     *
     * The word boundary at the end is load-bearing: without it, `lock_wait_timeout` would match
     * inside `innodb_lock_wait_timeout`, and a migration that bounded only its ROW locks would be
     * read as having bounded its METADATA lock. Those are different locks, and that is precisely
     * the confusion this rule family exists to prevent.
     *
     * Read off the canonical string because a plain `SET` is not a classified DDL kind.
     */
    public static function setsTimeout(MigrationStatementDigest $digest, string $timeout): bool
    {
        return preg_match('/(?<![a-z_])'.preg_quote($timeout, '/').'\b\s*(?:=|:=)/i', $digest->canonical) === 1
            && preg_match('/\bSET\b/i', $digest->canonical) === 1;
    }

    /** Whether every table this statement names was created earlier in the same migration. */
    private static function locksOnlyFreshTables(MigrationStatementDigest $digest, MigrationContext $migration): bool
    {
        $tables = array_values(array_filter(
            $digest->targets,
            static fn (StatementTarget $target): bool => $target->type === SchemaObjectType::Table,
        ));

        if ($tables === []) {
            return false;
        }

        return array_all(
            $tables,
            static fn (StatementTarget $target): bool => $migration->createsTable($target->qualifiedName()),
        );
    }
}
