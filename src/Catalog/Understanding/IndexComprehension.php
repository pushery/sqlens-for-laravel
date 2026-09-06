<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Understanding;

use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Catalog\SkipReason;
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
 * - **An expression index** indexes `lower(email)`, not `email`. A reader that saw the column list
 *   would call it a duplicate of `(email)` and be wrong in the direction that loses an index.
 * - **A method other than b-tree** answers different questions entirely. A GIN index over an array
 *   column is not a slower b-tree; the redundancy question is only meaningful inside one method.
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
            return new self(false, 'partial index predicate not compared: '.$predicate);
        }

        $expression = $index->getString('expression');

        if ($expression !== null && $expression !== '') {
            return new self(false, 'expression index — the indexed value is not the column: '.$expression);
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
            return new self(false, sprintf('%s index is not compared against b-tree indexes', $method));
        }

        $opclasses = $index->getString('operator_classes');

        if ($opclasses !== null && $opclasses !== '') {
            return new self(false, 'non-default operator class: '.$opclasses);
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
            return new self(false, 'prefix-length key — it indexes the first bytes of a column, not the column');
        }

        return self::complete();
    }

    /**
     * Every object with its comprehension recorded, and each gap named in the skips.
     *
     * The object STAYS in the reading — it was read, and a rule that only needs to know the index
     * exists is entitled to it. What the skip adds is that the reading is not a complete basis for
     * every question, which is what keeps an undetermined from disappearing into a green run.
     *
     * @param  list<SchemaObject>  $objects
     * @param  list<CatalogSkip>  $skips
     * @return list<SchemaObject>
     */
    public static function classify(array $objects, array &$skips): array
    {
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

                $skips[] = CatalogSkip::for(
                    SchemaObjectType::Index,
                    $object->qualifiedName,
                    SkipReason::NotUnderstood,
                    $comprehension->reason,
                );
            }

            $classified[] = $object->withAttributes($attributes);
        }

        return $classified;
    }
}
