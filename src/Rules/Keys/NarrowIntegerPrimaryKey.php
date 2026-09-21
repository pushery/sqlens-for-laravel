<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Keys;

use Pushery\SQLens\Catalog\TableMembers;
use Pushery\SQLens\Rules\Coverage\ForeignKeyIndexCoverage;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * Whether a table's primary key is an integer too narrow to grow into.
 *
 * ## Why this is shared rather than written twice
 *
 * The question is identical on both engines — is the key an integer, and is it the widest one — and
 * the two answers differ only in what the types are called. Written per driver, the two copies
 * would drift on the part that matters (which widths count) while looking maintained, and the
 * second one to be edited would be the one nobody remembered to.
 *
 * The rule classes stay per driver because the ID, the message and the remediation are per driver.
 * This holds the judgment.
 */
final readonly class NarrowIntegerPrimaryKey
{
    /**
     * The widths that run out, keyed by what the type is called on each engine.
     *
     * PostgreSQL exposes three integer types and MySQL five; the narrow ones are listed by name
     * rather than derived from a byte width, because the catalog reports names and a table that
     * mapped names to widths would be a second place to keep correct.
     *
     * `tinyint` is included for MySQL and is not a mistake: Laravel's `boolean()` is a `tinyint(1)`,
     * but a `tinyint` PRIMARY KEY is a 127-row ceiling, and that is worth a sentence whoever wrote it.
     *
     * @var list<string>
     */
    public const array NARROW = ['smallint', 'integer', 'int', 'mediumint', 'tinyint'];

    /** The types that do not run out in any practical sense — the answer this rule steers toward. */
    public const array WIDE = ['bigint'];

    /**
     * The largest value each narrow type holds, signed and unsigned.
     *
     * ⚠️ **MEASURED, not transcribed.** Every one of these eight was verified against MySQL 8.4.10 by
     * inserting the value and then the value plus one: the first is accepted, the second refused
     * under a strict mode. A ceiling table copied from memory is exactly the kind of number a reader
     * checks — and the message that carried the SIGNED `int` ceiling for an `INT UNSIGNED` key was
     * wrong by a factor of two, on the commonest shape the rule meets.
     *
     * The signed column is PostgreSQL's too: `smallint` stops at 32,767 and `integer` at
     * 2,147,483,647 there as well. The unsigned column is MySQL-only, because PostgreSQL has no
     * unsigned integers — so a PostgreSQL caller reads the signed side by construction rather than
     * by a rule somebody has to remember.
     *
     * @var array<string, array{signed: int, unsigned: int}>
     */
    public const array CEILING = [
        'tinyint' => ['signed' => 127, 'unsigned' => 255],
        'smallint' => ['signed' => 32767, 'unsigned' => 65535],
        'mediumint' => ['signed' => 8388607, 'unsigned' => 16777215],
        'int' => ['signed' => 2147483647, 'unsigned' => 4294967295],
        'integer' => ['signed' => 2147483647, 'unsigned' => 4294967295],
    ];

    /**
     * The ceiling of one narrow key, grouped for reading.
     *
     * Returns an empty string for a type this table does not know, and the caller then says nothing
     * about a limit rather than a wrong one. A missing entry is a gap in THIS table, not a fact about
     * the column, and inventing a number for it is the failure the whole class exists against.
     */
    public static function ceiling(string $type, bool $unsigned): string
    {
        $row = self::CEILING[strtolower($type)] ?? null;

        if ($row === null) {
            return '';
        }

        return number_format($unsigned ? $row['unsigned'] : $row['signed'], 0, '.', ',');
    }

    /**
     * The single-column integer primary key that is too narrow, or null.
     *
     * Single-column only, and deliberately. A composite key's range is the product of its parts, so
     * "too narrow" stops being a property of one column — and a rule that reported one anyway would
     * be arithmetic nobody asked it to do.
     *
     * ⚠️ **`unsigned` comes from the CATALOG, never from the type name.** The MySQL message names a
     * ceiling, and the signed one is half the unsigned one — so a rule that guessed would be wrong by
     * a factor of two on the commonest shape it meets, `increments()`, which produces `INT UNSIGNED`.
     * It is always `false` on PostgreSQL, which has no unsigned integers; a caller must treat that as
     * the answer rather than as a gap.
     *
     * @return array{column: string, type: string, unsigned: bool}|null
     */
    public static function of(SchemaObject $table): ?array
    {
        $primary = ForeignKeyIndexCoverage::parse($table->getString('primary_key') ?? '');
        $columns = array_values($primary)[0] ?? [];

        if (count($columns) !== 1) {
            return null;
        }

        $column = $columns[0];
        $types = ForeignKeyIndexCoverage::parse($table->getString('column_types') ?? '');
        $type = strtolower((string) ($types[$column][0] ?? ''));

        // An unread type is not a narrow one. A column nobody looked at must not become a finding,
        // or a gap in the reading decides what the report says.
        if (! in_array($type, self::NARROW, true)) {
            return null;
        }

        return ['column' => $column, 'type' => $type, 'unsigned' => self::isUnsigned($table, $column)];
    }

    /**
     * Whether the catalog reported this column as UNSIGNED.
     *
     * Read off `unsigned_columns`, the projection {@see TableMembers} carries
     * for exactly this question. Absent or empty means signed — which is the right default and the
     * only honest one on PostgreSQL, where no integer is unsigned.
     */
    private static function isUnsigned(SchemaObject $table, string $column): bool
    {
        $encoded = $table->getString('unsigned_columns') ?? '';

        return in_array($column, array_filter(
            array_map(trim(...), explode(';', $encoded)),
            static fn (string $c): bool => $c !== '',
        ), true);
    }

    /**
     * Whether this table is the framework's own migrations ledger.
     *
     * Laravel creates it from `DatabaseMigrationRepository::createRepository()` with
     * `increments('id')`, on every `migrate:install` and regardless of what the application would
     * prefer. Every Laravel application on PostgreSQL therefore carries a narrow key there, and
     * none of them can act on the advice: the table belongs to the framework, and the remediation
     * would mean writing against its own default on a table the application does not own.
     *
     * Matched on the UNQUALIFIED name, because that is the shape `database.migrations.table` has —
     * it names a table, never a schema. A same-named table in a second schema is exempt too, which
     * is the honest trade for not inventing a schema the setting does not carry.
     *
     * An empty name exempts nothing: a project that cleared the setting has said nothing about a
     * table, and "" would otherwise match every unqualified name in some spellings.
     */
    public static function isFrameworkMigrationsTable(SchemaObject $table, string $migrationsTable): bool
    {
        if (trim($migrationsTable) === '') {
            return false;
        }

        $qualified = $table->qualifiedName;
        $separator = strrpos($qualified, '.');
        $unqualified = $separator === false ? $qualified : substr($qualified, $separator + 1);

        return strtolower(trim($unqualified, '"')) === strtolower(trim($migrationsTable));
    }

    /**
     * `a` or `an` for a type name, because the message reads it aloud to somebody.
     *
     * Written from the type's own first letter rather than a list: the engines spell these in both
     * cases (`integer`, `INT`), and the article follows the letter either way. It was `a integer`
     * in every PostgreSQL finding until a consumer quoted it back.
     */
    public static function article(string $type): string
    {
        return in_array(strtolower(substr(trim($type), 0, 1)), ['a', 'e', 'i', 'o', 'u'], true) ? 'an' : 'a';
    }
}
