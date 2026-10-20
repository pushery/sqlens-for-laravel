<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\Support;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Canonical\StringLiteralMask;
use Pushery\SQLens\Drivers\Mysql\Canonical\MysqlCanonicalization;
use Pushery\SQLens\Subjects\MigrationContext;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The unique keys a migration declares on one table — as much as a static reader can honestly know.
 *
 * MySQL 8.4 refuses a foreign key whose referenced columns are not covered by a unique key of the
 * target table, so a rule judging a foreign key needs the target's keys. Those keys are spread
 * across the migration in a way that is easy to get wrong, and was measured rather than assumed:
 *
 * - `$table->id()` puts an inline `PRIMARY KEY` on the column, inside the `CREATE TABLE`;
 * - `$table->primary([…])` is FOLDED INTO the same `CREATE TABLE` as a `PRIMARY KEY (…)` clause;
 * - `$table->unique(…)` is not — even inside a `Schema::create` block it comes out as its own
 *   `ALTER TABLE … ADD UNIQUE …`.
 *
 * That asymmetry is the reason this reads the migration's whole statement STREAM rather than one
 * `CREATE TABLE`: a reader that stopped at the create would miss every unique key there is.
 *
 * ## The three-valued part
 *
 * {@see forTable()} returns null when the migration does not create the table at all. That is not
 * "no keys" — it is "not visible from here": the table exists on the server with whatever keys it
 * has, and this suite reads no server. The distinction is the whole point, because reading absence
 * as "no unique key" would flag every ordinary foreign key into an existing table.
 */
final readonly class UniqueKeyIndex
{
    /**
     * The unique key column lists a migration declares for a table, or null when the migration does
     * not create it.
     *
     * @return list<list<string>>|null each entry is one key's columns, in declaration order
     */
    public static function forTable(MigrationContext $migration, string $qualifiedName): ?array
    {
        if (! $migration->createsTable($qualifiedName)) {
            return null;
        }

        $keys = [];

        foreach ($migration->statements as $statement) {
            $target = $statement->soleTarget(SchemaObjectType::Table);
            if (! $target instanceof StatementTarget) {
                continue;
            }
            if ($target->qualifiedName() !== $qualifiedName) {
                continue;
            }

            $keys = [...$keys, ...self::keysIn($statement->canonical, $statement->kind)];
        }

        return $keys;
    }

    /**
     * Whether one of the declared keys covers exactly these columns.
     *
     * Exactly, not "starts with", and that is measured: MySQL 8.4 rejects a foreign key onto the
     * first column of a composite primary key just as it rejects one onto a non-unique index. A
     * prefix is not a unique key, whatever it looks like.
     *
     * @param  list<list<string>>  $keys
     * @param  list<string>  $columns
     */
    public static function covers(array $keys, array $columns): bool
    {
        return in_array($columns, $keys, true);
    }

    /**
     * The unique keys one canonical statement declares.
     *
     * @return list<list<string>>
     */
    private static function keysIn(string $canonical, ?StatementKind $kind): array
    {
        $statement = self::withoutStringLiterals($canonical);

        if ($kind === StatementKind::CreateTable) {
            return self::keysInCreateTable($statement);
        }

        // `ADD PRIMARY KEY (a, b)` and `ADD UNIQUE <name>(a, b)` — the two shapes a key arrives in
        // after the table exists, which for a unique key is always, even inside a create block.
        if (preg_match('/\bADD PRIMARY KEY\s*\(([^)]*)\)/', $statement, $primary) === 1) {
            return [self::columnList($primary[1])];
        }

        return preg_match('/\bADD UNIQUE\b[^(]*\(([^)]*)\)/', $statement, $unique) === 1
            ? [self::columnList($unique[1])]
            : [];
    }

    /**
     * The keys declared inside a `CREATE TABLE`: a `PRIMARY KEY (…)` or `UNIQUE [KEY|INDEX] [name] (…)`
     * entry, either one behind `CONSTRAINT name`, and a column definition that carries `PRIMARY KEY`
     * or `UNIQUE` itself, such as the inline key `$table->id()` folds in.
     *
     * Laravel's grammar writes a unique key as its own `ALTER TABLE`, so the clause forms come from
     * raw SQL. The list is split at the commas outside parentheses, because a type such as
     * `DECIMAL(8, 2)` or an `ENUM` carries commas of its own.
     *
     * @return list<list<string>>
     */
    private static function keysInCreateTable(string $statement): array
    {
        $keys = [];

        foreach (self::definitionEntries($statement) as $entry) {
            $entry = (string) preg_replace('/^CONSTRAINT\s+\S+\s+/', '', trim($entry));

            if (preg_match('/^(?:PRIMARY KEY|UNIQUE(?:\s+(?:KEY|INDEX))?(?:\s+[^\s(]+)?)\s*\(([^)]*)\)/', $entry, $clause) === 1) {
                $keys[] = self::columnList($clause[1]);

                continue;
            }

            if (preg_match('/^(?:KEY|INDEX|FULLTEXT|SPATIAL|FOREIGN|CHECK)\b/', $entry) === 1) {
                continue;
            }

            // A column definition: its name, then the type and the attributes, where `PRIMARY KEY`
            // or `UNIQUE` makes the column a key of its own. Parentheses hold the type's arguments,
            // a default or a generation expression, never a key attribute.
            if (preg_match('/^(\S+)\s+(.+)$/s', $entry, $column) === 1
                && preg_match('/\b(?:PRIMARY KEY|UNIQUE)\b/', (string) preg_replace('/\([^()]*\)/', '', $column[2])) === 1) {
                $keys[] = self::columnList($column[1]);
            }
        }

        return $keys;
    }

    /**
     * The entries of a `CREATE TABLE` definition list, split at the commas outside parentheses: the
     * list's own parenthesis is the first one, and it ends at its matching close. A statement without
     * one, such as `CREATE TABLE t LIKE u`, declares no entries, and an unclosed list is read to its
     * end.
     *
     * @return list<string>
     */
    private static function definitionEntries(string $statement): array
    {
        $open = strpos($statement, '(');

        if ($open === false) {
            return [];
        }

        $entries = [];
        $current = '';
        $depth = 0;

        foreach (str_split(substr($statement, $open + 1)) as $character) {
            if ($character === ')' && $depth === 0) {
                break;
            }

            if ($character === ',' && $depth === 0) {
                $entries[] = $current;
                $current = '';

                continue;
            }

            $depth += match ($character) {
                '(' => 1,
                ')' => -1,
                default => 0,
            };
            $current .= $character;
        }

        $entries[] = $current;

        return $entries;
    }

    /**
     * A parenthesized column list as its column names, unquoted and trimmed.
     *
     * @return list<string>
     */
    public static function columnList(string $raw): array
    {
        return array_values(array_filter(array_map(
            static fn (string $column): string => trim(trim($column), '`"'),
            explode(',', $raw),
        ), static fn (string $column): bool => $column !== ''));
    }

    private static function withoutStringLiterals(string $statement): string
    {
        return StringLiteralMask::forDriver(new MysqlCanonicalization)->apply($statement);
    }
}
