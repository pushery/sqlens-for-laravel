<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Keys;

use Pushery\SQLens\Rules\Coverage\ForeignKeyIndexCoverage;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A unique key that does not hold, because one of its foreign-key columns may be NULL.
 *
 * ## What actually happens, measured on both engines
 *
 * A unique index over `(tenant_id, customer_id)` looks like it says "one row per pair". Under the
 * default NULL treatment it does not. Measured on PostgreSQL 18.4 and MySQL 8.4 alike: three rows
 * carrying the same `tenant_id` and a NULL `customer_id` all insert successfully. The constraint
 * holds for exactly the rows that never needed it, and admits every row that did.
 *
 * That is not a matter of taste, and it is not visible from the schema: a reader sees `UNIQUE`, and
 * `UNIQUE` is one of the few words in SQL people believe without checking.
 *
 * ## Why the cut is this narrow, and what each narrowing costs
 *
 * "A nullable foreign key" on its own is the most false-positive-prone thing this package could
 * report — an optional reference is ordinary, correct, and everywhere. So three narrowings apply,
 * and each one is a decision to stay silent about real cases:
 *
 * - **The column must be inside a UNIQUE key.** Outside one, a nullable foreign key constrains
 *   nothing and claims nothing, so there is no contradiction to report.
 * - **The key must have at least two columns.** A single-column nullable unique key IS the
 *   optional-one-to-one idiom — `profile_id UNIQUE NULL`, `superseded_by_id UNIQUE NULL` — and it
 *   works precisely BECAUSE NULLs are distinct. Reporting it would be reporting the pattern for
 *   being itself.
 * - **Every member of the key must itself be a foreign-key column.** This is the narrowing that
 *   makes the rule shippable. A unique key mixing a foreign key with a payload column
 *   (`(user_id, slug)`) is an application's own uniqueness rule, and whether a NULL belongs in it is
 *   a domain question. A key made entirely of foreign keys is a RELATIONSHIP, and a relationship
 *   with a missing side is not a relationship.
 *
 * ## The primary-key half of the original design is deliberately absent
 *
 * The ticket proposed reporting a nullable column in a PRIMARY KEY as well. Measured: PostgreSQL
 * refuses it outright — `ERROR: column "a" is in a primary key` — and MySQL rewrites it silently.
 * The state is unreachable from a live catalog, so a rule that checked for it would be code that
 * cannot execute, which is worse than absent: it reads as coverage.
 */
final readonly class NullableKeyMember
{
    /**
     * Every unique key on this table that does not hold, with the nullable members that break it.
     *
     * @return array<string, list<string>> index name => its nullable foreign-key columns, sorted
     */
    public static function brokenKeys(SchemaObject $table): array
    {
        $nullable = self::columnSet($table->getString('nullable_columns'));
        $foreignKeyColumns = self::foreignKeyColumns($table);
        $broken = [];

        foreach (self::judgeable($table) as $index => $columns) {
            $offending = array_values(array_filter($columns, static fn (string $c): bool => in_array($c, $nullable, true)));

            // Every member a foreign-key column, or this is the application's own uniqueness rule
            // rather than a relationship, and whether a NULL belongs in it is a domain question.
            $allAreForeignKeys = $columns !== []
                && array_all($columns, static fn (string $c): bool => in_array($c, $foreignKeyColumns, true));

            if ($offending !== [] && $allAreForeignKeys) {
                sort($offending);
                $broken[$index] = $offending;
            }
        }

        ksort($broken);

        return $broken;
    }

    /**
     * The unique keys whose NULL treatment could not be read — the undetermined half.
     *
     * Reported rather than skipped: an index whose flag went unread is not an index that passed.
     * PostgreSQL's `NULLS NOT DISTINCT` makes the identical shape correct, so silence here would be
     * a verdict about a fact nobody has.
     *
     * @return list<string> index names, sorted
     */
    public static function unreadKeys(SchemaObject $table): array
    {
        $treatment = ForeignKeyIndexCoverage::parse($table->getString('unique_null_treatment') ?? '');
        $nullable = self::columnSet($table->getString('nullable_columns'));
        $foreignKeyColumns = self::foreignKeyColumns($table);
        $unread = [];

        foreach (self::candidates($table) as $index => $columns) {
            if (array_key_exists($index, $treatment)) {
                continue;
            }

            // Only the keys this rule would otherwise have judged. An unread flag on an index the
            // rule has nothing to say about is not a gap worth a reader's attention.
            $offends = array_any($columns, static fn (string $c): bool => in_array($c, $nullable, true));
            $allAreForeignKeys = array_all($columns, static fn (string $c): bool => in_array($c, $foreignKeyColumns, true));

            if ($offends && $allAreForeignKeys) {
                $unread[] = (string) $index;
            }
        }

        sort($unread);

        return $unread;
    }

    /**
     * The unique keys whose NULL treatment IS known to be distinct — the ones a verdict may rest on.
     *
     * @return array<string, list<string>> index name => its columns
     */
    private static function judgeable(SchemaObject $table): array
    {
        $treatment = ForeignKeyIndexCoverage::parse($table->getString('unique_null_treatment') ?? '');
        $judgeable = [];

        foreach (self::candidates($table) as $index => $columns) {
            if (($treatment[$index][0] ?? '') === 'distinct') {
                $judgeable[$index] = $columns;
            }
        }

        return $judgeable;
    }

    /**
     * The unique keys worth looking at at all: multi-column, and comparable.
     *
     * Comparable, because a partial or expression index was read completely but cannot be reasoned
     * about as a column list — and a rule that treated `lower(email)` as a column named
     * `lower(email)` would compare it against nothing forever, silently.
     *
     * @return array<string, list<string>> index name => its columns
     */
    private static function candidates(SchemaObject $table): array
    {
        $comparable = ForeignKeyIndexCoverage::parse($table->getString('comparable_indexes') ?? '');
        $candidates = [];

        foreach (ForeignKeyIndexCoverage::parse($table->getString('unique_indexes') ?? '') as $index => $columns) {
            // A single-column nullable unique key is the optional-one-to-one idiom, and it works
            // BECAUSE NULLs are distinct. Reporting it would be reporting the pattern for existing.
            if (count($columns) >= 2 && array_key_exists($index, $comparable)) {
                $candidates[$index] = $columns;
            }
        }

        return $candidates;
    }

    /** @return list<string> every column any foreign key on this table uses */
    private static function foreignKeyColumns(SchemaObject $table): array
    {
        $columns = [];

        foreach (ForeignKeyIndexCoverage::parse($table->getString('foreign_keys') ?? '') as $entry) {
            foreach ($entry as $column) {
                $columns[] = $column;
            }
        }

        return array_values(array_unique($columns));
    }

    /**
     * A plain `col; col` list as an array.
     *
     * @return list<string>
     */
    private static function columnSet(?string $encoded): array
    {
        if ($encoded === null || trim($encoded) === '') {
            return [];
        }

        return array_values(array_filter(
            array_map(trim(...), explode(';', $encoded)),
            static fn (string $c): bool => $c !== '',
        ));
    }
}
