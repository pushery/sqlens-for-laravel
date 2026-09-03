<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\Support;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
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
 * - `$table->unique(…)` is NOT — even inside a `Schema::create` block it comes out as its own
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
     * EXACTLY, not "starts with", and that is measured: MySQL 8.4 rejects a foreign key onto the
     * FIRST column of a composite primary key just as it rejects one onto a non-unique index. A
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
        // after the table exists, which for a unique key is ALWAYS, even inside a create block.
        if (preg_match('/\bADD PRIMARY KEY\s*\(([^)]*)\)/', $statement, $primary) === 1) {
            return [self::columnList($primary[1])];
        }

        return preg_match('/\bADD UNIQUE\b[^(]*\(([^)]*)\)/', $statement, $unique) === 1
            ? [self::columnList($unique[1])]
            : [];
    }

    /**
     * The keys declared inside a `CREATE TABLE`: the folded `PRIMARY KEY (…)` clause, and the
     * inline `PRIMARY KEY` that rides on a single column.
     *
     * @return list<list<string>>
     */
    private static function keysInCreateTable(string $statement): array
    {
        if (preg_match('/\bPRIMARY KEY\s*\(([^)]*)\)/', $statement, $clause) === 1) {
            return [self::columnList($clause[1])];
        }

        // The inline form: `<column> <type…> PRIMARY KEY`. The column is the last identifier-ish
        // word before the type, so the definition is read from the start of its list entry.
        return preg_match('/(?:\(|,)\s*(\S+)\s[^,]*?\bPRIMARY KEY\b/', $statement, $inline) === 1
            ? [[$inline[1]]]
            : [];
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
        return preg_replace("/'(?:[^']|'')*'/", "''", $statement) ?? $statement;
    }
}
