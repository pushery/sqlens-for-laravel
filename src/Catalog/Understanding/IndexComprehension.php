<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Understanding;

use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Catalog\SkipReason;
use Pushery\SQLens\Catalog\TableMembers;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Whether an index is understood well enough for a rule to REASON about it.
 *
 * The question is narrower than "was it read", and the difference is the whole point. Every index
 * below is read completely: its name, its table, its method, its columns. What varies is whether
 * comparing it to another index means anything — and a redundancy heuristic that compares two
 * indexes it does not understand produces a confident, wrong answer about which one to drop.
 *
 * ## The four things that make an index incomparable in v1
 *
 * Each was measured on a real PostgreSQL 18 before it was encoded here, because three of the four
 * look identical in `information_schema` and two look identical to each other in the naive reading:
 *
 * - **A partial index** carries a predicate, and `(email) WHERE note IS NOT NULL` does not cover
 *   what `(email)` covers. v1 does not compare predicates — a deliberate limit, not a gap — so the
 *   only honest answer about redundancy here is that there isn't one.
 * - **An expression index** indexes `lower(email)`, not `email` — and this one was narrowed after it
 *   was measured. The fear is a reader that sees the COLUMN and calls the index a duplicate of
 *   `(email)`; the PostgreSQL reading does not see the column, it sees `lower(email)`, because it
 *   asks `pg_get_indexdef()` per key position. So the refusal now covers the three ways the
 *   expression fails to ARRIVE rather than the fact that there is one — see
 *   {@see self::expressionLostOnTheWay()}.
 * - **A method other than b-tree** answers different questions entirely. A GIN index over an array
 *   column is not a slower b-tree; the redundancy question is only meaningful inside one method.
 *   Incomparable here means incomparable against a b-tree's column list — not incomparable against
 *   another index of its own kind, which is a narrower question the projection now asks separately.
 * - **A non-default operator class** changes what the index answers: `text_pattern_ops` serves
 *   `LIKE 'foo%'` and the default class does not. Two indexes on the same column with different
 *   classes are two different indexes. It is read AFTER the method, because a class only decides
 *   anything inside a method that is comparable at all — see the ordering note on `of()`.
 *
 * ## What is NOT a comprehension gap, stated rather than left implied
 *
 * An **invisible** MySQL index is understood completely — it exists, it costs writes, and the
 * optimizer ignores it. That is a fact for a rule to act on, not something the reader failed to
 * grasp, and classifying it as not-understood would hide a real finding behind an undetermined.
 * Same for a **generated column**: its type is read like any other column's, and the expression
 * behind it is something no v1 rule compares.
 */
final readonly class IndexComprehension
{
    /**
     * The index methods a redundancy question is meaningful inside.
     *
     * B-tree alone, and that is not a shortcut: the question "does this index cover what that one
     * covers" assumes both answer the same kind of query. Hash, GIN, GiST, BRIN, FULLTEXT and
     * SPATIAL each answer a different one.
     */
    private const array COMPARABLE_METHODS = ['btree'];

    private function __construct(
        public bool $fullyUnderstood,
        public ?string $reason,
        // Which of the two things an incomparable index can be, decided by the arm that said so and
        // never read back out of the sentence: a part that did not arrive (`not_understood`), or a
        // comparison left out on purpose (`not_comparable`). Null exactly when the index is complete.
        public ?SkipReason $skipReason = null,
    ) {}

    /** An index whose shape a rule can compare against another's. */
    public static function complete(): self
    {
        return new self(true, null);
    }

    /**
     * The verdict for one index object, read from the attributes both drivers produce.
     *
     * The order is deliberate: the FIRST reason found is the one reported, and the list runs from
     * the most consequential to the least. An expression index that is also partial is reported as
     * partial, because the predicate is what a reader has to think about first.
     */
    public static function of(SchemaObject $index): self
    {
        if ($index->type !== SchemaObjectType::Index) {
            // Not an index, so there is no index comprehension question. Answered rather than
            // refused: a caller sweeping a whole snapshot should not have to filter first.
            return self::complete();
        }

        $predicate = $index->getString('predicate');

        if ($predicate !== null && $predicate !== '') {
            // The VERDICT does not move: a partial index stays incomparable either way. What the
            // reading adds is which condition went uncompared, in a sentence rather than in the
            // server's spelling — and a predicate whose shape {@see IndexPredicate} does not know
            // says so by producing the bare line, which is worth reading as a signal.
            $reading = IndexPredicate::parse($predicate);

            return $reading instanceof IndexPredicate
                ? new self(false, sprintf('partial index predicate not compared — it selects %s: %s', $reading->describe(), $predicate), SkipReason::NotComparable)
                : new self(false, 'partial index predicate not compared: '.$predicate, SkipReason::NotUnderstood);
        }

        $expression = $index->getString('expression');

        if ($expression !== null && $expression !== '') {
            $lost = self::expressionLostOnTheWay($index, $expression);

            // Carried intact, so the comparison is against the expression rather than against the
            // column underneath it, and there is nothing left to refuse. See the method below.
            if ($lost !== null) {
                return new self(false, $lost, SkipReason::NotUnderstood);
            }
        }

        // The METHOD before the operator class, and the order is the finding rather than a tidy-up.
        //
        // An operator class only decides anything INSIDE a comparable method: two b-tree indexes on
        // one column with different classes are two different indexes, which is why the arm below
        // exists. Once the method itself is outside the question, naming the class points a reader
        // at a fact that cannot change the answer. Measured against PostgreSQL 18's `pg_opclass`:
        // `jsonb_path_ops` is defined for `gin` and for no other access method, so an index
        // carrying it is a GIN index by construction.
        //
        // Reported the other way round it misled a real reader, which is how this order got
        // measured: an audit said "non-default operator class: jsonb_path_ops" and the consumer
        // filed "know jsonb_path_ops" as the fix. It would have rewritten this sentence and left
        // the index exactly as incomparable as before.
        $method = $index->getString('method');

        if ($method !== null && ! in_array($method, self::COMPARABLE_METHODS, true)) {
            return new self(false, sprintf('%s index is not compared against b-tree indexes', $method), SkipReason::NotComparable);
        }

        $opclasses = $index->getString('operator_classes');

        if ($opclasses !== null && $opclasses !== '') {
            return new self(false, 'non-default operator class: '.$opclasses, SkipReason::NotComparable);
        }

        // A MySQL PREFIX-LENGTH key — `KEY (email(20))` — indexes the first 20 bytes rather than
        // the column, and `information_schema` reports the same COLUMN_NAME either way. So two
        // indexes that differ entirely look identical from their column lists, and a redundancy
        // heuristic would advise dropping one of them.
        //
        // Found by the negative corpus rather than reasoned out in advance: the rule reported a
        // prefix key as redundant to a full-column key on a real 8.4 catalog, which is exactly the
        // false positive that corpus exists to catch. PostgreSQL has no counterpart, so the flag is
        // simply absent there and this arm never fires.
        if ($index->getBool('prefixed_columns') === true) {
            return new self(false, 'prefix-length key — it indexes the first bytes of a column, not the column', SkipReason::NotComparable);
        }

        return self::complete();
    }

    /**
     * Whether every comprehension question EXCEPT the access method and its class is answered yes.
     *
     * The two left out are the two that can be made to cancel: an index is compared against others
     * of its own method and class, where both drop out of the question. Everything else here is a
     * gap that no grouping repairs — a predicate this cannot read, an expression that did not arrive,
     * a MySQL prefix-length key whose column list lies about what it indexes, and an index the server
     * itself marked invalid, which the planner ignores and which must never be offered as a cover.
     *
     * Deliberately NOT `! isFullyUnderstood()` plus a reason-string comparison. Reading which arm of
     * `of()` fired out of its sentence would make the projection depend on prose somebody will
     * reword, and the whole point of that sentence is that it can be reworded.
     */
    public static function comparableApartFromItsMethod(SchemaObject $index): bool
    {
        if ($index->type !== SchemaObjectType::Index) {
            return false;
        }

        if ($index->getBool('valid') === false || $index->getBool('prefixed_columns') === true) {
            return false;
        }

        $predicate = $index->getString('predicate');

        if ($predicate !== null && $predicate !== '') {
            return false;
        }

        $expression = $index->getString('expression');

        return $expression === null
            || $expression === ''
            || self::expressionLostOnTheWay($index, $expression) === null;
    }

    /**
     * Whether every comprehension question EXCEPT the index's condition is answered yes.
     *
     * The mirror of {@see self::comparableApartFromItsMethod()}, for the other attribute that can be
     * made to cancel. Two partial indexes under one condition cover the same rows, so the condition
     * drops out of the question, and nothing else does. What survives is compared by LEFT PREFIX,
     * which is b-tree arithmetic over plain key positions, so every other reason an index cannot be
     * compared still has to be absent: an access method other than b-tree, a non-default operator
     * class, an expression that did not arrive, a prefix-length key, an index the server marked
     * invalid.
     *
     * ## The operator class is the one that bit
     *
     * `pg_get_indexdef(oid, n, true)` prints a key position WITHOUT its operator class. Measured on
     * PostgreSQL 18.0: `(email text_pattern_ops) WHERE state IN ('closed', 'void')` and `(email)`
     * under the same condition both arrive as `email`, so a grouping that asked only whether the
     * condition could be read put them in one universe with identical column lists, and the rule
     * reported one of two different indexes as a duplicate of the other. `text_pattern_ops` serves
     * `LIKE 'foo%'` and the default class does not; dropping either loses something.
     */
    public static function comparableApartFromItsPredicate(SchemaObject $index): bool
    {
        if ($index->type !== SchemaObjectType::Index) {
            return false;
        }

        if ($index->getBool('valid') === false || $index->getBool('prefixed_columns') === true) {
            return false;
        }

        if (! self::comparesByPrefix($index->getString('method'))) {
            return false;
        }

        $opclasses = $index->getString('operator_classes');

        if ($opclasses !== null && $opclasses !== '') {
            return false;
        }

        $expression = $index->getString('expression');

        return $expression === null
            || $expression === ''
            || self::expressionLostOnTheWay($index, $expression) === null;
    }

    /**
     * Whether a redundancy question inside this access method may be answered by a LEFT PREFIX.
     *
     * B-tree alone, and a method nobody named counts as one — an engine that does not report the
     * access method must not have every index treated as exotic by a field it never fills.
     *
     * Public because the grouping in {@see TableMembers} asks the same
     * question from the other side: an index this returns false for is not incomparable, it is
     * comparable only against indexes of its own method. One fact, one owner, two readers.
     */
    public static function comparesByPrefix(?string $method): bool
    {
        return $method === null || $method === '' || in_array($method, self::COMPARABLE_METHODS, true);
    }

    /**
     * Why this expression index cannot be compared after all, or null when it can be.
     *
     * ## The blanket refusal was too wide, and the measurement says by how much
     *
     * It was written against a reader that sees the COLUMN — one that would call `(lower(email))` a
     * duplicate of `(email)` and drop the wrong one. That is the right fear about the wrong reader.
     * The PostgreSQL reading asks `pg_get_indexdef()` per key position, which yields the expression
     * itself, so `(lower(email))` arrives spelled `lower(email)` and compares against `(email)` as
     * the different thing it is. Measured on 18.4, and the server normalizes the spelling on the way
     * out: `LOWER(Email)` and `lower(email)` both come back as `lower(email)`, so two indexes
     * written differently for the same expression are recognizably the same index without this
     * package normalizing anything.
     *
     * What that leaves is not a general doubt but two specific ways the expression fails to arrive
     * intact, each of which really does make the comparison meaningless:
     *
     * - **It never reached the key columns.** MySQL's `information_schema` reports a functional index
     *   with a null `COLUMN_NAME`, and the reading records the expression beside the index rather
     *   than inside its column list. So `(lower(a))` and `(lower(b))` would both arrive as an EMPTY
     *   list and compare equal, and a functional index would look like a duplicate of a plain one.
     *   This is the arm that keeps the widening PostgreSQL-only without a driver name in it.
     * - **Its key positions do not balance.** A reading whose positions cannot be told apart from
     *   pieces of one another is not a list anything downstream may compare, and it is refused rather
     *   than repaired — see {@see self::isOneKeyPosition()}.
     *
     * ## Two refusals that were retired, because the separators stopped being a problem
     *
     * An expression holding the character that separates key positions used to arrive as pieces:
     * `COALESCE(heading, '')` is one position with a comma inside. One holding the character that
     * separates members — a `';'` literal is legal in an index expression — took the member list
     * apart. Both were refused. Both lists are now split only at their TOP level, outside parentheses
     * and quotes ({@see TopLevelList}), so these expressions arrive whole and are compared like any
     * other. A consumer's search index over `title || ' ' || COALESCE(heading, '')` measured what the
     * old refusal cost: an ordinary index, reported as not understood on every run.
     *
     * ⚠️ **The obvious test for the first arm — does the expression text appear among the key
     * columns — is WRONG, and it took a real reading to show it.** The two facts come from two
     * different deparsers, and on PostgreSQL 18.4 they disagree: `pg_get_expr(indexprs)` renders
     * `lower((display_name)::text)` where `pg_get_indexdef()` per position renders
     * `lower(display_name::text)`. A string comparison therefore fails on every expression carrying
     * a cast, and the widening would have shipped doing nothing. What is asked instead is whether an
     * expression is VISIBLE in the list at all, beside the driver's own declaration that it dropped
     * one.
     */
    private static function expressionLostOnTheWay(SchemaObject $index, string $expression): ?string
    {
        $tokens = TopLevelList::split($index->getString('key_columns') ?? '', ',');

        // Two ways of establishing the same thing, and both are wanted. The flag is the reading's
        // own statement that it put the expression somewhere else; the search is the fail-closed
        // half, for a future driver that drops one without saying so. Measured on 18.4 over five
        // shapes — a cast, a concatenation, a negation, a JSON arrow and a function call — every
        // deparsed expression carries a parenthesis, either the call's own or the pair PostgreSQL
        // wraps a bare expression in. An unquoted column name never can.
        if ($index->getBool('functional') === true || ! self::anExpressionIsVisibleAmong($tokens)) {
            return 'expression index — the expression is recorded beside the index rather than among its key columns, so comparing this index would compare the columns it does NOT index: '.$expression;
        }

        foreach ($tokens as $token) {
            if (! self::isOneKeyPosition($token)) {
                return 'expression index — its key positions do not balance, so they cannot be told apart from pieces of one another: '.$expression;
            }
        }

        return null;
    }

    /**
     * Whether at least one of these key positions is an expression rather than a column name.
     *
     * @param  list<string>  $tokens
     */
    private static function anExpressionIsVisibleAmong(array $tokens): bool
    {
        return array_any($tokens, fn (string $token): bool => str_contains($token, '('));
    }

    /**
     * Whether this token is a WHOLE key position rather than a piece of one.
     *
     * Balance on the parentheses and on both kinds of quote, and nothing cleverer: a complete
     * expression closes everything it opens. The list is already split only at its top level, so a
     * balanced reading never produces a piece that fails here. What does is a reading that was itself
     * cut or truncated, which {@see TopLevelList} hands back split flat so that this check refuses it
     * instead of every later position being swallowed into one.
     */
    private static function isOneKeyPosition(string $token): bool
    {
        return substr_count($token, '(') === substr_count($token, ')')
            && substr_count($token, '"') % 2 === 0
            && substr_count($token, "'") % 2 === 0;
    }

    /**
     * Every object with its comprehension recorded, and each index a comparison MISSED named in the skips.
     *
     * The object STAYS in the reading — it was read, and a rule that only needs to know the index
     * exists is entitled to it.
     *
     * ## A skip says a comparison did not happen, not that the index is unusual
     *
     * The verdict recorded on the index is unchanged: a GIN index, a partial index and one under a
     * non-default operator class are still not comparable against a b-tree's column list, and
     * `isFullyUnderstood()` still says so. The SKIP answers a narrower question — did a redundancy
     * comparison that means something go unmade for this index — and for two shapes the answer used
     * to be yes when it was no:
     *
     * - An index of another access method, read intact, is compared against the indexes of its own
     *   method and operator class. Alone in that universe it has nothing to be a duplicate of, and
     *   "not compared against b-tree indexes" names a comparison with no meaning.
     * - A partial index, read intact, is compared against every index under its own condition, and
     *   never against an unconditional one, which is a decision rather than a gap. The comparison
     *   that genuinely does not happen is against a partial index under a DIFFERENT condition, which
     *   would need an implication rule, so the skip is recorded when its table carries one, and only
     *   then.
     *
     * Reported from a consumer's schema where both sat alone and read "unknown, not fine" on every
     * run, which a strict pipeline turned into a permanent red.
     *
     * @param  list<SchemaObject>  $objects
     * @param  list<CatalogSkip>  $skips
     * @return list<SchemaObject>
     */
    public static function classify(array $objects, array &$skips): array
    {
        $conditions = self::groupableConditionsByTable($objects);
        $classified = [];

        foreach ($objects as $object) {
            if ($object->type !== SchemaObjectType::Index) {
                $classified[] = $object;

                continue;
            }

            $comprehension = self::of($object);

            // Recorded on EVERY index, true or false. An attribute that appears only when something
            // is wrong cannot be relied on to be there when it is right, and `isFullyUnderstood()`
            // would then be answering "nobody looked" with "yes".
            $attributes = ['understood' => $comprehension->fullyUnderstood];

            if (! $comprehension->fullyUnderstood) {
                $attributes['not_understood'] = (string) $comprehension->reason;

                $missed = self::comparisonMissed($object, $comprehension, $conditions[$object->parent ?? ''] ?? []);

                if ($missed !== null) {
                    $skips[] = CatalogSkip::for(
                        SchemaObjectType::Index,
                        $object->qualifiedName,
                        $missed[0],
                        $missed[1],
                    );
                }
            }

            $classified[] = $object->withAttributes($attributes);
        }

        return $classified;
    }

    /**
     * The comparison that went unmade for this index — why, and in which sentence — or null when none that means anything did.
     *
     * The reason is decided by the arm that stopped the comparison, not by the index's first reason:
     * a partial index that stays out of its group because of an expression that did not arrive is
     * `not_understood`, however readable its condition, because the expression is what a reader has
     * to look at.
     *
     * @param  list<string>  $conditionsOnItsTable  the conditions its table's partial indexes are grouped under
     * @return array{SkipReason, string}|null
     */
    private static function comparisonMissed(SchemaObject $index, self $comprehension, array $conditionsOnItsTable): ?array
    {
        $reason = (string) $comprehension->reason;
        $predicate = $index->getString('predicate');

        if ($predicate !== null && $predicate !== '') {
            $reading = IndexPredicate::parse($predicate);

            // A condition nobody could read is never grouped, so nothing about this index was compared.
            if (! $reading instanceof IndexPredicate) {
                return [SkipReason::NotUnderstood, $reason];
            }

            // Something besides the condition keeps it out of its group, and the sentence names that
            // something: the condition is not what a reader has to act on here. An index the server
            // marked invalid has no other arm to name, and is left out on purpose.
            if (! self::comparableApartFromItsPredicate($index)) {
                $apart = self::of($index->withAttributes(['predicate' => null]));

                return [$apart->skipReason ?? SkipReason::NotComparable, $apart->reason ?? $reason];
            }

            $others = count(array_diff($conditionsOnItsTable, [$reading->normalized]));

            return $others === 0 ? null : [SkipReason::NotComparable, sprintf(
                'partial index compared only against the indexes under its own condition — it selects %s; %s on this table would need an implication rule, and none is built: %s',
                $reading->describe(),
                $others === 1 ? 'one other condition' : $others.' other conditions',
                $predicate,
            )];
        }

        if (! self::comparesByPrefix($index->getString('method')) && self::comparableApartFromItsMethod($index)) {
            // Compared inside its method and operator class, or alone there with nothing to duplicate.
            return null;
        }

        return [$comprehension->skipReason ?? SkipReason::NotComparable, $reason];
    }

    /**
     * The distinct conditions each table's partial indexes are grouped under.
     *
     * The same admission {@see TableMembers} makes for its condition groups: a readable condition on an
     * index nothing else keeps apart. A condition on an index that cannot be grouped decides nothing
     * about which comparisons its neighbors miss.
     *
     * @param  list<SchemaObject>  $objects
     * @return array<string, list<string>> table => its conditions
     */
    private static function groupableConditionsByTable(array $objects): array
    {
        $conditions = [];

        foreach ($objects as $object) {
            $predicate = $object->getString('predicate');

            if ($predicate === null || $predicate === '' || ! self::comparableApartFromItsPredicate($object)) {
                continue;
            }

            $normalized = IndexPredicate::parse($predicate)?->normalized;

            if ($normalized !== null) {
                $conditions[$object->parent ?? ''][] = $normalized;
            }
        }

        return array_map(static fn (array $found): array => array_values(array_unique($found)), $conditions);
    }
}
