<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Indexes;

use Closure;
use Pushery\SQLens\Catalog\TableMembers;
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
 * ## The one thing a partial index DOES conclude, and the three it does not
 *
 * Two partial indexes whose normalized predicates are identical cover exactly the same rows, so the
 * predicate cancels and the columns decide. That is arithmetic — same condition, same row set — and
 * it is the only conclusion drawn about a partial index anywhere in this rule.
 *
 * Everything else about them stays excluded, and each exclusion is a decision rather than a gap:
 *
 * - **Two DIFFERENT predicates** is an implication question, and implication is not built. The pair
 *   is never formed.
 * - **A partial index against an UNCONDITIONAL one** is the tempting case. As a statement about rows
 *   it is true that the full index covers the partial one; as ADVICE it is not, because the partial
 *   index can be orders of magnitude smaller and somebody kept it that way on purpose. Dropping it
 *   is a loss, not a tidy-up, and that judgment is not this rule's to make.
 * - **An expression index** is unchanged: the indexed value is not the column.
 *
 * A partial index is still reported as not understood by {@see IndexComprehension}, and that is not
 * a contradiction. Comprehension answers whether the index can be compared against a column list in
 * GENERAL; this rule makes one narrow comparison that does not need the general answer.
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
        $protected = self::protectedNames($table);
        $redundant = self::within(
            self::sorted(ForeignKeyIndexCoverage::parse($table->getString('comparable_indexes') ?? '')),
            $protected,
        );

        // Each group of partial indexes is its own comparison universe, and they are kept apart on
        // purpose: an index from one group can never be reported against one from another, because
        // that would be an implication claim rather than an arithmetic one.
        foreach (self::predicateGroups($table) as $group) {
            $redundant = [...$redundant, ...self::within($group, $protected)];
        }

        // The same universes one attribute along — a group of GIN indexes, of GiST indexes, of
        // FULLTEXT indexes. They are kept in their own loop because what may be CONCLUDED inside
        // one is weaker: only an identical column list, never a prefix. See self::identicalWithin().
        foreach (self::methodGroups($table) as $group) {
            $redundant = [...$redundant, ...self::identicalWithin($group, $protected)];
        }

        ksort($redundant);

        return $redundant;
    }

    /**
     * The redundant indexes inside one comparison universe, judged by LEFT PREFIX.
     *
     * A universe is a set of indexes that cover the same rows as each other — every unconditional
     * comparable index, or one group of partial indexes carrying the same condition. Whether the
     * membership was earned by having no predicate or by sharing one is settled before this runs;
     * here they are simply column lists.
     *
     * Every member of such a universe is a b-tree, which is what makes the prefix relation a
     * statement about coverage rather than about ordering. {@see self::identicalWithin()} is the
     * same sweep for a universe where that is not true.
     *
     * @param  array<string, list<string>>  $universe
     * @param  list<string>  $protected
     * @return array<string, string>
     */
    private static function within(array $universe, array $protected): array
    {
        return self::pairsIn($universe, $protected, self::covers(...));
    }

    /**
     * The redundant indexes inside a universe where only IDENTITY concludes anything.
     *
     * The members share an access method and an operator class and nothing else is known about how
     * that method searches — so the pair that may be reported is the pair with the SAME column list,
     * which is the same index written twice. A prefix here would be a claim about a structure this
     * package has not measured, made in the direction that tells somebody to drop an index.
     *
     * @param  array<string, list<string>>  $universe
     * @param  list<string>  $protected
     * @return array<string, string>
     */
    private static function identicalWithin(array $universe, array $protected): array
    {
        return self::pairsIn($universe, $protected, self::isTheSameIndex(...));
    }

    /**
     * One sweep over a universe, pairing each candidate with the first index that supersedes it.
     *
     * The sweep is shared and the JUDGMENT is passed in, which is the arrangement that matters: the
     * bookkeeping — skip the protected, skip the empty, stop at the first cover, report deterministic
     * pairs — is identical for every universe, and the arithmetic is exactly what is not.
     *
     * @param  array<string, list<string>>  $universe
     * @param  list<string>  $protected
     * @param  Closure(list<string>, list<string>, string, string): bool  $supersedes
     * @return array<string, string>
     */
    private static function pairsIn(array $universe, array $protected, Closure $supersedes): array
    {
        $redundant = [];

        foreach ($universe as $candidate => $columns) {
            if (in_array($candidate, $protected, true)) {
                continue;
            }
            if ($columns === []) {
                continue;
            }
            foreach ($universe as $cover => $coverColumns) {
                if ($cover === $candidate) {
                    continue;
                }
                if (! $supersedes($columns, $coverColumns, (string) $candidate, (string) $cover)) {
                    continue;
                }
                $redundant[(string) $candidate] = (string) $cover;

                break;
            }
        }

        return $redundant;
    }

    /**
     * The partial indexes of this table, split into one set per shared condition.
     *
     * Two partial indexes whose normalized predicates are identical cover exactly the same rows, so
     * the predicate cancels and the columns decide. That is arithmetic, not a heuristic — and it is
     * the ONLY thing about a partial index this rule concludes. The grouping itself is done by
     * {@see TableMembers}, whose projection also decides what never enters
     * a group: an unconditional index, a predicate shape the reading refuses, and an index alone
     * under its condition.
     *
     * A group of one is dropped here as well as there. It cannot produce a pair, and letting one
     * through would mean a token appearing in the projection that no comparison can use.
     *
     * @return list<array<string, list<string>>>
     */
    private static function predicateGroups(SchemaObject $table): array
    {
        return self::universes($table, 'same_predicate_indexes', 'index_predicate_groups');
    }

    /**
     * The indexes of this table that share an ACCESS METHOD and operator class, one set per pair.
     *
     * ## What the group buys, and the line it does not cross
     *
     * A GIN index is not comparable against a b-tree, and that stays true. It is comparable against
     * another GIN index of the same operator class — and the only thing this rule concludes there is
     * that an IDENTICAL column list means the same index twice. Nothing about coverage, nothing
     * about prefixes: the caller {@see self::identicalWithin()} is the weaker arithmetic, and it is
     * a separate method precisely so the stronger one cannot be reached from here by accident.
     *
     * ## Why not prefixes, when PostgreSQL would allow more
     *
     * Measured on 18.4: a GIN index on `(tags, doc)` serves a query touching `doc` alone, so GIN
     * coverage is a SUBSET relation and the left prefix used above understates it. Both relations
     * would be sound for GIN. Neither is knowable for an access method an extension brings with it,
     * and this rule advises somebody to DROP an index — the direction where being wrong costs a
     * sequential scan on production. Identity is the one claim that holds whatever the method does
     * with its columns.
     *
     * The grouping itself is done by {@see TableMembers}, which also decides what never enters a
     * group: a b-tree, an index whose reading was incomplete, one the server marked invalid, and one
     * alone under its method.
     *
     * @return list<array<string, list<string>>>
     */
    private static function methodGroups(SchemaObject $table): array
    {
        return self::universes($table, 'same_method_indexes', 'index_method_groups');
    }

    /**
     * One projection pair read back into comparison universes.
     *
     * Both groupings encode the same way — a member list and a parallel token list, joined by index
     * name — because both answer the same question about a different attribute. An index named in
     * one and not the other is dropped rather than guessed at.
     *
     * @param  string  $memberAttribute  the `name(cols)` projection of the grouped indexes
     * @param  string  $tokenAttribute  the `name(gN)` projection saying which group each is in
     * @return list<array<string, list<string>>>
     */
    private static function universes(SchemaObject $table, string $memberAttribute, string $tokenAttribute): array
    {
        $columns = ForeignKeyIndexCoverage::parse($table->getString($memberAttribute) ?? '');
        $tokens = ForeignKeyIndexCoverage::parse($table->getString($tokenAttribute) ?? '');
        $grouped = [];

        foreach ($tokens as $index => $token) {
            $key = $token[0] ?? '';
            $name = (string) $index;

            if ($key === '' || ! array_key_exists($name, $columns)) {
                continue;
            }

            $grouped[$key][$name] = $columns[$name];
        }

        ksort($grouped);

        return array_values(array_map(
            self::sorted(...),
            array_filter($grouped, static fn (array $group): bool => count($group) > 1),
        ));
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
     * Whether these two are the SAME index written twice — the only claim a shared method supports.
     *
     * Equal lists, in order, and the tie broken by name exactly as above so one finding comes out of
     * a pair instead of two. Order is required rather than ignored: this cannot know whether the
     * method treats `(a, b)` and `(b, a)` alike, and two indexes it cannot prove identical are two
     * indexes.
     *
     * @param  list<string>  $candidate
     * @param  list<string>  $cover
     */
    private static function isTheSameIndex(array $candidate, array $cover, string $candidateName, string $coverName): bool
    {
        return $candidate === $cover && $candidateName > $coverName;
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
