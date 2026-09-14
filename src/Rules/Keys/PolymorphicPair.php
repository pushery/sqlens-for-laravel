<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Keys;

use Pushery\SQLens\Rules\Coverage\ForeignKeyIndexCoverage;
use Pushery\SQLens\Rules\Pedantic\ImplicitCast;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A polymorphic column pair, and whether an index serves the only lookup it is ever used for.
 *
 * ## What a polymorphic relation actually asks the database
 *
 * A polymorphic relation resolves by BOTH columns at once. The id is unique only within one type —
 * `commentable_id = 7` names a post and an invoice and a user — so no relation can be resolved from
 * it alone, and every access adds the type. Without an index over the pair each of those reads the
 * whole table, and the cost grows with the table rather than with the number of relations.
 *
 * Nothing in the schema hints at it. A foreign key at least announces the relationship it belongs
 * to; a polymorphic pair is two ordinary columns whose meaning lives entirely in the application.
 *
 * ## Why the TYPE column has to come first, and why the reverse is a separate finding
 *
 * A b-tree index serves a left prefix. `(commentable_type, commentable_id)` therefore answers both
 * the paired lookup and a type-only one; `(commentable_id, commentable_type)` answers the paired
 * lookup too — and the id-only lookup nobody performs. Both are indexes over the same two columns
 * and only one of them is the one `morphs()` writes.
 *
 * The distinction matters to the reader more than to the planner, which is why the rules report it
 * as its own sentence: "there is no index here" sends somebody to write one, and "your index is the
 * wrong way round" sends them to replace one. Told the first when the second is true, they add a
 * second index over the same columns and `L7`'s redundancy rule then reports THAT.
 *
 * ## What identifies a pair, and the limit of it
 *
 * Two columns sharing a prefix: `<p>_type` holding characters, and `<p>_id` holding an integer, a
 * `uuid`, or the fixed-width character forms Laravel's `uuidMorphs()` and `ulidMorphs()` write on
 * MySQL. That is a NAMING convention, and the catalog can prove the columns exist and what they
 * hold — never that `morphs()` wrote them. A pair that merely happens to be named this way is a
 * false positive by construction and belongs on the ignore list; no amount of catalog reading can
 * tell the two apart, and pretending otherwise would be the more expensive mistake.
 *
 * The id side deliberately does not accept `varchar` or `text`. Laravel writes neither for a morph
 * id, and accepting them would make every `<p>_type`/`<p>_id` pair whose id is a slug a finding.
 */
final readonly class PolymorphicPair
{
    /**
     * The fixed-width character types a morph id is written as.
     *
     * `char(36)` is `uuidMorphs()` on MySQL and `char(26)` is `ulidMorphs()`; PostgreSQL gets a
     * native `uuid` for the first and `char(26)` for the second. The declared length is not part of
     * the type here — a project that widened the column still has a morph id.
     *
     * @var list<string>
     */
    private const array FIXED_WIDTH_ID_TYPES = ['uuid', 'char', 'character', 'bpchar', 'binary'];

    /**
     * The types a `_type` column holds. A morph type stores a class name or an alias.
     *
     * @var list<string>
     */
    private const array TYPE_COLUMN_TYPES = [
        'varchar', 'character varying', 'text', 'char', 'character', 'bpchar', 'tinytext', 'mediumtext', 'longtext',
    ];

    private function __construct(
        public string $prefix,
        public string $typeColumn,
        public string $idColumn,
    ) {}

    /**
     * Every polymorphic pair on this table, in the order the type columns sort.
     *
     * @return list<self>
     */
    public static function of(SchemaObject $table): array
    {
        $types = ForeignKeyIndexCoverage::parse($table->getString('column_types') ?? '');
        $pairs = [];

        foreach ($types as $column => $declared) {
            if (! str_ends_with($column, '_type') || ! self::holdsCharacters($declared[0] ?? '')) {
                continue;
            }

            $prefix = substr($column, 0, -strlen('_type'));

            if ($prefix === '') {
                continue;
            }

            $idColumn = $prefix.'_id';

            if (! self::holdsAnIdentifier($types[$idColumn][0] ?? '')) {
                continue;
            }

            $pairs[$column] = new self($prefix, $column, $idColumn);
        }

        ksort($pairs);

        return array_values($pairs);
    }

    /**
     * The columns in the order an index has to carry them.
     *
     * @return list<string>
     */
    public function columns(): array
    {
        return [$this->typeColumn, $this->idColumn];
    }

    /**
     * …and in the order that answers a lookup nobody makes, which is its own finding.
     *
     * @return list<string>
     */
    public function reversed(): array
    {
        return [$this->idColumn, $this->typeColumn];
    }

    /**
     * Sort every pair on this table into the two findings and the silence.
     *
     * Two lists rather than one, because they send a reader to different edits: a pair with NO
     * index needs one written, a pair whose index leads with the ID needs that index REPLACED.
     * Reported as one finding, somebody adds a second index over the same two columns and `L7`
     * then reports it as redundant to the one they already had.
     *
     * A pair that is covered appears in neither, and so does a table that carries no pair at all —
     * this rule says nothing about a schema that is not polymorphic.
     *
     * @return array{missing: list<self>, reversed: list<self>}
     */
    public static function assess(SchemaObject $table): array
    {
        $indexes = self::comparableIndexesOf($table);
        $missing = [];
        $reversed = [];

        foreach (self::of($table) as $pair) {
            if (ForeignKeyIndexCoverage::isCovered($pair->columns(), $indexes)) {
                continue;
            }

            if (ForeignKeyIndexCoverage::isCovered($pair->reversed(), $indexes)) {
                $reversed[] = $pair;

                continue;
            }

            $missing[] = $pair;
        }

        return ['missing' => $missing, 'reversed' => $reversed];
    }

    /**
     * The indexes a rule may reason about as coverage, as bare column lists.
     *
     * `comparable_indexes` rather than `indexes`, for the reason the projection separates them: a
     * partial, expression or non-default-operator-class index is a real index that serves no such
     * lookup, and counting one would leave the rule silent about a table that really does scan.
     *
     * @return list<list<string>>
     */
    public static function comparableIndexesOf(SchemaObject $table): array
    {
        return array_values(ForeignKeyIndexCoverage::parse($table->getString('comparable_indexes') ?? ''));
    }

    /**
     * ONE sentence for the table, naming every pair and the edit each one needs.
     *
     * One verdict rather than one per pair, for the reason the foreign-key sister learned the hard
     * way: results are deduplicated by rule id and LOCATION, a catalog finding is located at the
     * OBJECT, and a second verdict here would be dropped without a word. A table with two bare
     * polymorphic pairs would have reported one, and the other would have gone on scanning.
     *
     * @param  array{missing: list<self>, reversed: list<self>}  $assessment
     */
    public static function sentence(string $table, array $assessment): string
    {
        $parts = [];

        foreach ($assessment['missing'] as $pair) {
            $parts[] = sprintf(
                '`%s` and `%s` are a polymorphic pair with no index over them, so every read through that '
                .'relation scans %s. Add an index on (`%s`, `%s`).',
                $pair->typeColumn, $pair->idColumn, $table, $pair->typeColumn, $pair->idColumn,
            );
        }

        foreach ($assessment['reversed'] as $pair) {
            $parts[] = sprintf(
                '`%s` and `%s` are a polymorphic pair whose index leads with the id, which answers a lookup '
                .'nothing performs: the id is unique only within one type. REPLACE that index with one on '
                .'(`%s`, `%s`) rather than adding a second over the same two columns.',
                $pair->typeColumn, $pair->idColumn, $pair->typeColumn, $pair->idColumn,
            );
        }

        return implode(' ', $parts);
    }

    /** A column that holds a class name or an alias. */
    private static function holdsCharacters(string $declared): bool
    {
        return in_array(self::normalize($declared), self::TYPE_COLUMN_TYPES, true);
    }

    /** …and one that holds what a morph id is written as, on either engine. */
    private static function holdsAnIdentifier(string $declared): bool
    {
        if ($declared === '') {
            return false;
        }

        return ImplicitCast::integerWidth($declared) !== null
            || in_array(self::normalize($declared), self::FIXED_WIDTH_ID_TYPES, true);
    }

    /** Lower-cased and stripped of a declared length, which is not part of the type. */
    private static function normalize(string $declared): string
    {
        $bare = strtolower(trim($declared));
        $paren = strpos($bare, '(');

        return trim($paren === false ? $bare : substr($bare, 0, $paren));
    }
}
