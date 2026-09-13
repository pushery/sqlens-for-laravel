<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Coverage;

use Pushery\SQLens\Catalog\Understanding\TopLevelList;

/**
 * Whether an index covers a foreign key — the one question, decided in one place.
 *
 * PostgreSQL does not index the REFERENCING side of a foreign key. Every `DELETE` or `UPDATE` on
 * the parent then scans the child table, and on a table of any size that is the difference between
 * a deploy and an outage. The fact is old and well documented; what makes it worth a rule is that
 * nothing in a migration file hints at it.
 *
 * ## Left prefix, not "contains"
 *
 * A B-tree index on `(a, b)` serves a lookup on `a`, and on `(a, b)` — not on `b` alone. So a
 * foreign key on `(a)` is covered by an index on `(a, b)`, and a foreign key on `(a, b)` is NOT
 * covered by an index on `(a)`. Order matters in both directions, and a "does the index mention
 * these columns" test would be wrong in the direction that reports a table as safe while it scans.
 *
 * ## What deliberately does NOT count as coverage
 *
 * Only indexes the reading already judged comparable are offered here — a partial index, an
 * expression index and one with a non-default operator class are excluded upstream. That exclusion
 * is the cautious direction: those indexes exist, and treating them as coverage would leave the
 * rule silent about a table that really does scan. The opposite mistake — reporting a foreign key
 * that IS covered — is loud and self-correcting; this one is silent and permanent.
 */
final readonly class ForeignKeyIndexCoverage
{
    /**
     * Whether any of these indexes covers the foreign key's columns.
     *
     * @param  list<string>  $foreignKeyColumns  in the order the constraint declares them
     * @param  list<list<string>>  $indexColumnLists  each index's KEY columns, in order
     */
    public static function isCovered(array $foreignKeyColumns, array $indexColumnLists): bool
    {
        if ($foreignKeyColumns === []) {
            // No columns is not "covered by everything" — it is a foreign key nobody could read, and
            // the caller has to treat it as undetermined rather than let this answer yes.
            return false;
        }

        return array_any($indexColumnLists, fn (array $indexColumns): bool => self::isLeftPrefix($foreignKeyColumns, $indexColumns));
    }

    /**
     * Parse the encoded member list a table carries: `name(col, col); other(col)`.
     *
     * The catalog attaches its members as one string because a snapshot has to serialize to stable
     * JSON. Parsing it here rather than in each rule keeps one reading of that shape — two would be
     * free to disagree about whitespace, and the one that disagreed would report a phantom.
     *
     * Both separators are honored only at the TOP level ({@see TopLevelList}). An expression index
     * carries its expression as a key position, and an expression may hold a comma inside a call or
     * a semicolon inside a string literal; split flat, one index became several members with names
     * and columns nobody wrote.
     *
     * @return array<string, list<string>> member name => its columns, in order
     */
    public static function parse(string $encoded): array
    {
        $members = [];

        foreach (TopLevelList::split($encoded, ';') as $entry) {
            $entry = trim($entry);
            if ($entry === '') {
                continue;
            }
            if (! str_ends_with($entry, ')')) {
                continue;
            }

            $open = strpos($entry, '(');

            if ($open === false) {
                continue;
            }

            $name = trim(substr($entry, 0, $open));
            $columns = substr($entry, $open + 1, -1);

            if ($name === '') {
                continue;
            }

            $members[$name] = array_values(array_filter(
                TopLevelList::split($columns, ','),
                static fn (string $column): bool => $column !== '',
            ));
        }

        return $members;
    }

    /**
     * Whether the needle is the LEFT prefix of the haystack — the whole matching rule.
     *
     * @param  list<string>  $needle
     * @param  list<string>  $haystack
     */
    private static function isLeftPrefix(array $needle, array $haystack): bool
    {
        if (count($needle) > count($haystack)) {
            return false;
        }

        return array_all(
            $needle,
            static fn (string $column, int $position): bool => ($haystack[$position] ?? null) === $column,
        );
    }
}
