<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Usage;

use Pushery\SQLens\Catalog\Understanding\TopLevelList;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Puts the position of each primary key's counter where a rule can see it.
 *
 * A separate step after the catalog reading, for the reason {@see KeyCounterReading} gives: the
 * value moves, and the snapshot must not. The audit runner reads both and joins them here, the way
 * {@see IndexUsageProjection} joins the index scan counts.
 *
 * ## The attributes, and what an absence means
 *
 * - `key_counter` — a {@see KeyCounterState} value, or `none` when the reading was complete and
 *   found no counter that can run out behind this table's key.
 * - `key_counter_source`, `key_counter_value`, `key_counter_ceiling` and `key_counter_failure` —
 *   the fields of the {@see KeyCounter}, null where the state carries no such fact.
 * - `key_counter_references` — the counter behind each key this table's foreign keys point at,
 *   one entry per referencing column: `column(state, value, source)`, with `-` for a value the
 *   state does not carry. It is the one fact here that is not the table's own: a column narrower
 *   than the key it references runs out when the parent's sequence passes the column's ceiling,
 *   and a rule judges one object at a time. A column absent from it points at a key no counter
 *   that was read fills.
 *
 * A reading that failed as a whole marks every table `unread` and names the failure, because
 * "nothing found" and "nobody could look" must not read the same. A table without any `key_counter`
 * attribute was never projected at all, which a rule treats as unread as well.
 */
final readonly class KeyCounterProjection
{
    /** The reading was complete, and no counter that can run out feeds this table's key. */
    public const string NONE = 'none';

    /**
     * Every table with the counter behind its primary key attached.
     *
     * @param  list<SchemaObject>  $objects
     * @return list<SchemaObject>
     */
    public static function attachTo(array $objects, KeyCounterReading $reading): array
    {
        // The single-column primary key of each table, so a reference is matched to the counter that
        // fills the key it points at and to nothing else.
        $keyColumns = [];

        foreach ($objects as $object) {
            $columns = array_values(self::members($object->getString('primary_key') ?? ''))[0] ?? [];

            if ($object->type === SchemaObjectType::Table && count($columns) === 1) {
                $keyColumns[$object->qualifiedName] = $columns[0];
            }
        }

        $attached = [];

        foreach ($objects as $object) {
            if ($object->type !== SchemaObjectType::Table) {
                $attached[] = $object;

                continue;
            }

            if (! $reading->available) {
                $attached[] = $object->withAttributes([
                    'key_counter' => KeyCounterState::Unread->value,
                    'key_counter_failure' => $reading->failure,
                ]);

                continue;
            }

            $counter = $reading->counterOf($object->qualifiedName);

            $attached[] = $object->withAttributes(($counter instanceof KeyCounter
                ? [
                    'key_counter' => $counter->state->value,
                    'key_counter_source' => $counter->source,
                    'key_counter_value' => $counter->lastValue,
                    'key_counter_ceiling' => $counter->ceiling,
                    'key_counter_failure' => $counter->failure,
                ]
                : ['key_counter' => self::NONE])
                + ['key_counter_references' => self::references($object, $reading, $keyColumns)]);
        }

        return $attached;
    }

    /**
     * The counter behind each key this table's foreign keys point at, encoded per referencing column.
     *
     * Read off `foreign_key_types`, whose entries pair a local column with the qualified column it
     * references. A reference counts only where that column is the referenced table's single-column
     * primary key, because that is the key the counter fills.
     *
     * @param  array<string, string>  $keyColumns  table qualified name => its single primary-key column
     */
    private static function references(SchemaObject $table, KeyCounterReading $reading, array $keyColumns): string
    {
        $entries = [];

        foreach (self::members($table->getString('foreign_key_types') ?? '') as $sides) {
            if (count($sides) !== 2) {
                continue;
            }

            $local = self::nameOf($sides[0]);
            $far = self::nameOf($sides[1]);
            $separator = strrpos($far, '.');

            if ($separator === false || isset($entries[$local])) {
                continue;
            }

            $farTable = substr($far, 0, $separator);
            $counter = $reading->counterOf($farTable);

            if (($keyColumns[$farTable] ?? null) !== substr($far, $separator + 1) || ! $counter instanceof KeyCounter) {
                continue;
            }

            $entries[$local] = sprintf(
                '%s(%s, %s, %s)',
                $local,
                $counter->state->value,
                $counter->lastValue ?? '-',
                $counter->source,
            );
        }

        ksort($entries);

        return implode('; ', $entries);
    }

    /**
     * `name(member, member); name(member)` read into its members, the encoding TableMembers writes.
     *
     * Split at the top level only, the way {@see TopLevelList} reads every list of this shape, so a
     * comma or a semicolon inside a member cannot cut it in two.
     *
     * @return array<string, list<string>>
     */
    private static function members(string $encoded): array
    {
        $members = [];

        foreach (TopLevelList::split($encoded, ';') as $entry) {
            $open = strpos($entry, '(');

            if ($open === false || ! str_ends_with($entry, ')') || $open === 0) {
                continue;
            }

            $members[substr($entry, 0, $open)] = array_values(array_filter(
                TopLevelList::split(substr($entry, $open + 1, -1), ','),
                static fn (string $member): bool => $member !== '',
            ));
        }

        return $members;
    }

    /** The column name of a `name=type` member, or the member itself when it carries no type. */
    private static function nameOf(string $member): string
    {
        $equals = strpos($member, '=');

        return $equals === false ? $member : substr($member, 0, $equals);
    }
}
