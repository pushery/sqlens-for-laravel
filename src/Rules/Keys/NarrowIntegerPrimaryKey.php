<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Keys;

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
     * The single-column integer primary key that is too narrow, or null.
     *
     * Single-column only, and deliberately. A composite key's range is the product of its parts, so
     * "too narrow" stops being a property of one column — and a rule that reported one anyway would
     * be arithmetic nobody asked it to do.
     *
     * @return array{column: string, type: string}|null
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
        return in_array($type, self::NARROW, true)
            ? ['column' => $column, 'type' => $type]
            : null;
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
