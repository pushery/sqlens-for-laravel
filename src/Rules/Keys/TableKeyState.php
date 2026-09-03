<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Keys;

use Pushery\SQLens\Catalog\TableMembers;
use Pushery\SQLens\Rules\Coverage\ForeignKeyIndexCoverage;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * Whether a table has a usable key — three-valued, because two of the three answers are real and
 * only one of them is "no key".
 *
 * ## One meaning of "keyed", read from two places
 *
 * The same question is asked of a migration that CREATES a table and of a live table in the
 * catalog. The inputs could hardly differ more — one is a canonical `CREATE TABLE` string, the
 * other a set of catalog facts — but the MEANING of the answer must not, or a project would be
 * told a table is fine by one suite and broken by the other. So both readings live here, side by
 * side, returning the same three values.
 *
 * What differs is how much each input can settle. A migration cannot say whether a `UNIQUE` key's
 * columns are nullable, so it answers `Undetermined`; the catalog knows, so it answers. That is
 * the whole point of running the question against both.
 *
 * The reading is deliberately coarse: the presence of a `PRIMARY KEY` clause anywhere in the
 * statement. Laravel's MySQL grammar folds the key INTO the create, both for `id()` (an inline
 * `primary key` on the column) and for `$table->primary([…])` (a `primary key (a, b)` clause at
 * the end of the column list) — measured, and pinned by a characterization test. So one statement
 * settles the question for a table born in a migration, and a parser that walked the column list
 * would buy nothing this does not already answer.
 *
 * String literals are masked before the scan, and that is not caution for its own sake: the
 * canonicalization leaves literal CONTENT untouched by design, so a column defaulting to
 * `'PRIMARY KEY'` would otherwise vouch for a key the table does not have — a false NEGATIVE,
 * the direction that matters.
 */
enum TableKeyState
{
    /** A `PRIMARY KEY` is declared in the statement. */
    case Keyed;

    /** No key of any kind is declared — the case the rule flags. */
    case Unkeyed;

    /**
     * The statement does not settle it: the table is created FROM another one (`LIKE`, `SELECT`)
     * so its keys come from the source, or it declares a `UNIQUE` key but no `PRIMARY KEY` and
     * InnoDB's promotion of a `UNIQUE NOT NULL` index to the clustered index decides the outcome.
     */
    case Undetermined;

    /** Read a canonical `CREATE TABLE`. */
    public static function inCreateTable(string $canonical): self
    {
        $statement = self::withoutStringLiterals($canonical);

        if (preg_match('/\bPRIMARY KEY\b/', $statement) === 1) {
            return self::Keyed;
        }

        // A table whose structure comes from elsewhere. The keys come with it, and this statement
        // describes neither — so it is unknown here, never "none".
        if (preg_match('/\b(?:LIKE|SELECT)\b/', $statement) === 1) {
            return self::Undetermined;
        }

        return preg_match('/\bUNIQUE\b/', $statement) === 1 ? self::Undetermined : self::Unkeyed;
    }

    /**
     * Read a live table from the catalog facts {@see TableMembers} attaches.
     *
     * A `PRIMARY KEY` settles it. Failing that, a `UNIQUE` index over columns that are all NOT NULL
     * is a real substitute: PostgreSQL accepts exactly such an index as a `REPLICA IDENTITY`, and
     * InnoDB promotes the first one to the clustered index. Both engines require it to be a plain,
     * complete index — partial, expression, prefix and invalid indexes cannot serve — which is why
     * only the ones the reading judged comparable are considered.
     *
     * Nullability is where this has to be careful. A column the reading never saw is not a nullable
     * column; it is a column nobody looked at, and treating the two alike would let a gap in the
     * reading decide a finding. So an otherwise-qualifying index whose columns' nullability is
     * unknown yields `Undetermined`, and a definite substitute anywhere on the table still wins
     * over it.
     */
    public static function inCatalog(SchemaObject $table): self
    {
        $columns = self::decodeList($table->getString('columns') ?? '');

        // No column was read at all. A real table has columns, so this says something about the
        // READING, not about the table — and reporting a table nobody read as unkeyed would be a
        // finding invented out of a blind spot.
        if ($columns === []) {
            return self::Undetermined;
        }

        if (ForeignKeyIndexCoverage::parse($table->getString('primary_key') ?? '') !== []) {
            return self::Keyed;
        }

        $comparable = ForeignKeyIndexCoverage::parse($table->getString('comparable_indexes') ?? '');
        $nullable = self::decodeList($table->getString('nullable_columns') ?? '');
        $unknownNullability = false;

        foreach (ForeignKeyIndexCoverage::parse($table->getString('unique_indexes') ?? '') as $name => $indexColumns) {
            if (! array_key_exists($name, $comparable)) {
                continue;
            }

            $verdict = self::allNotNull($indexColumns, $columns, $nullable);

            if ($verdict === true) {
                return self::Keyed;
            }

            $unknownNullability = $unknownNullability || $verdict === null;
        }

        return $unknownNullability ? self::Undetermined : self::Unkeyed;
    }

    /**
     * Whether every one of these columns is known NOT NULL — true, false, or null for "unknown".
     *
     * @param  list<string>  $indexColumns
     * @param  list<string>  $known  every column the reading saw
     * @param  list<string>  $nullable  the ones it saw and found nullable
     */
    private static function allNotNull(array $indexColumns, array $known, array $nullable): ?bool
    {
        if ($indexColumns === []) {
            return null;
        }

        $unknown = false;

        foreach ($indexColumns as $column) {
            if (in_array($column, $nullable, true)) {
                return false;
            }

            $unknown = $unknown || ! in_array($column, $known, true);
        }

        return $unknown ? null : true;
    }

    /**
     * Decode a plain `a; b; c` list — the same separator the member encoding uses, without the
     * parentheses a member with columns of its own carries.
     *
     * @return list<string>
     */
    private static function decodeList(string $encoded): array
    {
        return array_values(array_filter(
            array_map(trim(...), explode(';', $encoded)),
            static fn (string $entry): bool => $entry !== '',
        ));
    }

    /** Replace every string literal with an empty one, so a scan reads syntax and not data. */
    private static function withoutStringLiterals(string $statement): string
    {
        return preg_replace("/'(?:[^']|'')*'/", "''", $statement) ?? $statement;
    }
}
