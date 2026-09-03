<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Indexes;

use Pushery\SQLens\Catalog\Understanding\IndexComprehension;
use Pushery\SQLens\Rules\Coverage\ForeignKeyIndexCoverage;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * An index whose work another index already does.
 *
 * ## The cost is real and paid on every write
 *
 * A B-tree index on `(a)` beside one on `(a, b)` answers nothing the second cannot. It still has to
 * be maintained: every insert writes it, every update that touches `a` writes it, it occupies its
 * own pages in cache, and on PostgreSQL it is one more relation for vacuum to walk. The read side
 * gains nothing at all.
 *
 * ## Why this rule is nearly all exclusions
 *
 * A naive "is this a left prefix" test is wrong on the first real schema it meets, and wrong in the
 * expensive direction: it tells somebody to DROP an index. Dropping the wrong one turns a lookup
 * into a sequential scan on production, and the advice came with this tool's name on it.
 *
 * So the comparison is only ever made between indexes the reading already judged **comparable** —
 * {@see IndexComprehension} excludes a partial index, an
 * expression index, one with a non-default operator class, one whose method is not b-tree, and one
 * PostgreSQL marked invalid. Each of those exclusions is a named catalog skip rather than a silent
 * omission, so a schema full of partial indexes is told that they were not compared, instead of
 * being handed a clean report.
 *
 * ## The four things that stop a pair from being redundant
 *
 * - **Either index is not comparable.** Covered above; the pair is never formed.
 * - **The candidate is UNIQUE or the primary key.** Dropping it would change what the schema
 *   ALLOWS, not just what it costs, and that is a different conversation from a performance
 *   finding. A unique index may still be the one that COVERS another — a unique key on `(a, b)`
 *   serves lookups on `(a)` — so it is excluded as a victim and kept as a candidate cover.
 * - **The candidate carries an INCLUDE payload.** Measured: `(a) INCLUDE (b)` and `(a)` report the
 *   same key columns, so without the payload flag this rule would recommend dropping the more
 *   useful of the two.
 * - **It is not a strict left prefix.** A B-tree on `(a, b)` serves `(a)`, and does not serve `(b)`.
 *   Order is the fact, not a detail.
 *
 * ## Equal column lists, and why the tie is broken by NAME
 *
 * Two indexes on exactly the same columns are genuinely redundant, and neither is the obvious
 * victim. Picking by name — the later one reported against the earlier — is arbitrary, and it is
 * arbitrary DETERMINISTICALLY, which is the property that matters: the same schema produces the
 * same report on Tuesday as on Monday, and the message names both so a reader picks for themselves.
 */
final readonly class RedundantIndex
{
    /**
     * Every redundant index on this table, each with the index that already covers it.
     *
     * @return array<string, string> redundant index => the index that covers it, sorted by name
     */
    public static function on(SchemaObject $table): array
    {
        $comparable = self::sorted(ForeignKeyIndexCoverage::parse($table->getString('comparable_indexes') ?? ''));
        $protected = self::protectedNames($table);
        $redundant = [];

        foreach ($comparable as $candidate => $columns) {
            if (in_array($candidate, $protected, true)) {
                continue;
            }
            if ($columns === []) {
                continue;
            }
            foreach ($comparable as $cover => $coverColumns) {
                if ($cover === $candidate) {
                    continue;
                }
                if (! self::covers($columns, $coverColumns, $candidate, (string) $cover)) {
                    continue;
                }
                $redundant[(string) $candidate] = (string) $cover;

                break;
            }
        }

        ksort($redundant);

        return $redundant;
    }

    /**
     * Whether `$cover` serves everything `$candidate` serves.
     *
     * A strict left prefix always does. Equal lists do too, and there the tie is broken by name so
     * exactly one of the pair is reported and the choice does not move between runs.
     *
     * @param  list<string>  $candidate
     * @param  list<string>  $cover
     */
    private static function covers(array $candidate, array $cover, string $candidateName, string $coverName): bool
    {
        if (count($candidate) > count($cover)) {
            return false;
        }

        foreach ($candidate as $position => $column) {
            if (($cover[$position] ?? null) !== $column) {
                return false;
            }
        }

        // Identical lists: report the later NAME against the earlier, so a pair produces one
        // finding rather than two mutually-accusing ones, and always the same one.
        return count($candidate) < count($cover) || $candidateName > $coverName;
    }

    /**
     * The indexes that must never be reported as redundant, whatever their columns.
     *
     * @return list<string>
     */
    private static function protectedNames(SchemaObject $table): array
    {
        $names = [
            // Dropping either changes what the schema ALLOWS rather than what it costs.
            ...array_keys(ForeignKeyIndexCoverage::parse($table->getString('primary_key') ?? '')),
            ...array_keys(ForeignKeyIndexCoverage::parse($table->getString('unique_indexes') ?? '')),
            // The payload is invisible in a column list, so an index carrying one is never the
            // victim — see the class docblock.
            ...array_keys(ForeignKeyIndexCoverage::parse($table->getString('payload_indexes') ?? '')),
        ];

        return array_values(array_unique(array_map(strval(...), $names)));
    }

    /**
     * The parsed members in a stable key order.
     *
     * The projection is already sorted, but a rule that DEPENDS on an ordering has to establish it
     * rather than inherit it: the nested loop below picks the first cover it finds, and "first" has
     * to mean the same thing on every run or the report moves without the schema moving.
     *
     * @param  array<string, list<string>>  $members
     * @return array<string, list<string>>
     */
    private static function sorted(array $members): array
    {
        ksort($members);

        return $members;
    }
}
