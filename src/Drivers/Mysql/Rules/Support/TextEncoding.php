<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\Support;

use Pushery\SQLens\Catalog\TableMembers;
use Pushery\SQLens\Drivers\Mysql\Rules\L6\CharacterSetServerNotUtf8mb4Rule;
use Pushery\SQLens\Rules\Coverage\ForeignKeyIndexCoverage;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * How a MySQL object stores text, read off the catalog at the three levels that decide it.
 *
 * ## Three levels, because MySQL inherits down all three
 *
 * A column takes its character set and collation from its table, a table from its database, and a
 * database from the server. Each level may override the one above it, so a schema can be correct at
 * two levels and wrong at the third — and the wrong one is usually the database default, which no
 * existing table reveals: it decides what the NEXT table gets.
 *
 * That is why the rules that read this judge a database object and a table object, and why the
 * server level is somebody else's rule ({@see CharacterSetServerNotUtf8mb4Rule}
 * reads the variable, which is a different subject with a different remedy).
 *
 * ## Why the column facts come off the TABLE
 *
 * A finding is deduplicated by rule id and location, and a catalog location is the object. A rule
 * emitting one verdict per offending column would therefore have all but the first dropped without a
 * word, and a reader would fix the one column named and believe the table was done. So the columns
 * travel projected onto their table ({@see TableMembers}), and the rules
 * report one finding per table listing every column on it. It is also the better report: converting
 * a table's columns is one decision about one table, not forty.
 *
 * TEST-VISIBLE NOTE: a column absent from these lists holds no characters at all — an `int`, a
 * `date`, a `blob`. That is not the same as a column whose encoding went unread, and no caller may
 * treat it as one.
 */
final readonly class TextEncoding
{
    /**
     * Whether this object states a DATABASE's own default rather than a table's or a column's.
     *
     * The scope is read from the attribute rather than inferred from the object having no parent:
     * PostgreSQL emits collation objects at two scopes, and a check that keyed on the shape instead
     * of the stated fact would start answering for the wrong ones the moment a second scope arrived.
     */
    public static function isDatabaseDefault(SchemaObject $object): bool
    {
        return $object->type === SchemaObjectType::Collation
            && $object->getString('collation_scope') === 'database';
    }

    /** @return array<string, string> column name => its character set, for the columns that have one */
    public static function columnCharsets(SchemaObject $table): array
    {
        return self::projected($table, 'column_charsets');
    }

    /** @return array<string, string> column name => its collation, for the columns that have one */
    public static function columnCollations(SchemaObject $table): array
    {
        return self::projected($table, 'column_collations');
    }

    /**
     * One `name(value); name(value)` projection as a map, sorted by column name.
     *
     * Sorted here rather than at each call site, because the order columns are named in ends up in a
     * published message: two runs over an unchanged schema have to produce the same sentence, and a
     * projection's order is the reader's insertion order rather than a promise.
     *
     * @return array<string, string>
     */
    private static function projected(SchemaObject $table, string $attribute): array
    {
        $values = [];

        foreach (ForeignKeyIndexCoverage::parse($table->getString($attribute) ?? '') as $column => $entries) {
            $value = $entries[0] ?? '';

            if ($value !== '') {
                $values[(string) $column] = $value;
            }
        }

        ksort($values);

        return $values;
    }
}
