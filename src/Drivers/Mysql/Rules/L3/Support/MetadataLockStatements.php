<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L3\Support;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Canonical\StringLiteralMask;
use Pushery\SQLens\Drivers\Mysql\Canonical\MysqlCanonicalization;
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
     * How long a lock wait stops being a wait and becomes an outage, in seconds.
     *
     * A DECLARED expectation rather than a measured one, and it is declared once, here, so the lint
     * rule and the preflight check cannot disagree about one `SET`. MySQL ships
     * `lock_wait_timeout = 31536000`, one year, which at deploy time is indistinguishable from
     * waiting forever. An hour is the line: past it, the deploy has already failed in every way that
     * matters to whoever is watching it, and the metadata lock it holds has blocked every DDL behind
     * it for that whole time.
     *
     * @see https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html
     */
    public const int SESSION_WAIT_CEILING_SECONDS = 3600;

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
        // The LAST statement that touches the variable decides, not any of them: a later
        // `SET … = DEFAULT` takes a bound away again.
        $bounded = false;

        foreach ($stream as $digest) {
            if ($digest->index < $gateIndex && self::sessionTimeoutIn($digest->canonical, $timeout) !== null) {
                $bounded = self::setsTimeout($digest, $timeout);
            }
        }

        return $bounded;
    }

    /**
     * Whether the statement bounds its own session's value of exactly the named variable, to an hour
     * at most ({@see self::SESSION_WAIT_CEILING_SECONDS}).
     *
     * The name is compared whole: `lock_wait_timeout` must never be read inside
     * `innodb_lock_wait_timeout`, or a migration that bounded only its ROW locks would be read as
     * having bounded its METADATA lock. Those are different locks, and that is precisely the
     * confusion this rule family exists to prevent. And `SET GLOBAL`, `= DEFAULT` or a year bound
     * nothing for the session running the migration; {@see self::sessionTimeoutIn()} reads them for
     * this rule and for the preflight check alike.
     *
     * Read off the canonical string because a plain `SET` is not a classified DDL kind.
     *
     * **Over the masked string, and that is the whole difference between a rule and a grep.**
     * Scanning `$digest->canonical` directly would count a statement that merely contains the words
     * as setting the timeout:
     *
     * ```sql
     * INSERT INTO notes (body) VALUES ('set lock_wait_timeout = 5');
     * ALTER TABLE users MODIFY email VARCHAR(320);
     * ```
     *
     * Both patterns would match inside the literal, `timeoutSetBefore()` would report a preamble that
     * does not exist, and MY.L3.MISSING_LOCK_WAIT_TIMEOUT would go silent on the ALTER — a false green
     * on the one rule whose entire job is to notice the missing bound.
     *
     * It needs no raw SQL and no double quote: `->insert()` with that string produces it, and the
     * false silence would survive for the rest of the migration because the gate index only has to be
     * larger. A double-quoted literal reaches it a second way.
     */
    public static function setsTimeout(MigrationStatementDigest $digest, string $timeout): bool
    {
        $seconds = self::sessionTimeoutIn($digest->canonical, $timeout)['seconds'] ?? null;

        return $seconds !== null && $seconds <= self::SESSION_WAIT_CEILING_SECONDS;
    }

    /**
     * What a statement does to its own session's value of the named variable, or null when it leaves
     * it alone.
     *
     * `seconds` is the value it sets, or null for one that bounds nothing this can read: `DEFAULT`,
     * which on MySQL 8.4 is a year, or an expression. A `GLOBAL` or `PERSIST` assignment changes what
     * LATER connections start with, never this session, so it leaves the session's value alone. The
     * scope keyword carries over to the following assignments of the same `SET`, as the manual says,
     * and `@@SESSION.`, `@@LOCAL.` or a bare `@@` name the session for that one assignment.
     *
     * Only a statement that BEGINS with `SET`, at the start or after a `;`, and read off the masked
     * text, so the words inside a value are data and `UPDATE t SET …` is no session setting.
     *
     * @return array{seconds: int|null}|null
     */
    public static function sessionTimeoutIn(string $canonical, string $variable): ?array
    {
        $masked = StringLiteralMask::forDriver(new MysqlCanonicalization)->apply($canonical);
        $found = null;

        foreach (explode(';', $masked) as $statement) {
            if (preg_match('/^\s*SET\s+(.*)$/is', $statement, $set) !== 1) {
                continue;
            }

            $scope = 'SESSION';

            foreach (self::assignments($set[1]) as $assignment) {
                if (preg_match('/^(?:(?<keyword>GLOBAL|SESSION|LOCAL|PERSIST|PERSIST_ONLY)\s+)?(?<at>@@(?:(?<qualifier>GLOBAL|SESSION|LOCAL|PERSIST|PERSIST_ONLY)\.)?)?(?<name>[a-z_][a-z0-9_]*)\s*(?::=|=)\s*(?<value>.*)$/is', $assignment, $part) !== 1) {
                    continue;
                }

                if ($part['keyword'] !== '') {
                    $scope = strtoupper($part['keyword']);
                }

                $effective = $part['qualifier'] !== '' ? strtoupper($part['qualifier']) : ($part['at'] !== '' ? 'SESSION' : $scope);

                if (strcasecmp($part['name'], $variable) !== 0 || ! in_array($effective, ['SESSION', 'LOCAL'], true)) {
                    continue;
                }

                $value = trim($part['value']);
                $found = ['seconds' => ctype_digit($value) ? (int) $value : null];
            }
        }

        return $found;
    }

    /**
     * The comma-separated assignments of one `SET`, a comma inside parentheses left where it is.
     *
     * @return list<string>
     */
    private static function assignments(string $list): array
    {
        $parts = [];
        $depth = 0;
        $current = '';

        foreach (str_split($list) as $char) {
            if ($char === ',' && $depth === 0) {
                $parts[] = trim($current);
                $current = '';

                continue;
            }

            $depth += match ($char) {
                '(' => 1,
                ')' => -1,
                default => 0,
            };
            $current .= $char;
        }

        $parts[] = trim($current);

        return $parts;
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
