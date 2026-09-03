<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Convention;

use Pushery\SQLens\Rules\Coverage\ForeignKeyIndexCoverage;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * One judgment about a foreign-key column's name, shared by the PostgreSQL and MySQL rules.
 *
 * ## The FK-ness is read from the CONSTRAINT, never from the name
 *
 * This is the whole difficulty, and getting it wrong makes the rule useless in a way that looks
 * like it works. A rule that decided "this column carries a relation" by seeing `_id` at the end
 * would find exactly the columns that already satisfy it, and would be blind to `user`, `owner` and
 * `parent` — the names it exists for. It would pass on every schema, including the ones it was
 * written to fix.
 *
 * So both paths ask the schema instead:
 *
 * - **audit** reads the `foreign_keys` attribute the catalog attached to the table, which is a list
 *   of real constraints and the columns each one covers;
 * - **lint** judges only a statement whose canonical kind IS `add_foreign_key`, and takes its
 *   columns from the statement's own key columns.
 *
 * Neither can be satisfied by a name, which is what makes the rule able to fail.
 *
 * ## A composite foreign key is NOT judged, and that is a decision
 *
 * A multi-column key references a compound key on the other side, and the parts of a compound key
 * carry their own meaning: `(country_code, area_code)` is a reference whose columns are named after
 * what they hold. `_id` is a convention about a SURROGATE key — one column standing in for a row —
 * so demanding it of every member of a natural-key reference would report a false positive on
 * exactly the schemas that modeled their keys most carefully.
 *
 * Stated as a limitation on the rule rather than left as a silence: a reader who sees a composite
 * key go unreported should be able to find out that it was skipped on purpose.
 *
 * ## Two cases that need NO special handling, measured rather than assumed
 *
 * - **Self-referential.** `parent_id` referencing the same table ends in `_id` and passes on its
 *   own merits. The ticket that asked for this rule expected a special case; there is nothing to
 *   special-case, and adding one would be a branch no schema can reach.
 * - **Polymorphic.** Laravel's `commentable_id` ends in `_id` and passes. Its partner
 *   `commentable_type` carries no foreign key at all — it cannot, since it names a class rather
 *   than a row — so it is invisible to a rule that reads constraints. An exemption list for
 *   polymorphic columns would therefore exempt nothing, while suggesting the rule needs help it
 *   does not need.
 */
final readonly class ForeignKeyIdSuffix
{
    /**
     * The suffix a single-column foreign key is expected to end with.
     *
     * Laravel's relation resolution derives it from the related model's name, so a column that
     * departs from it makes every relation on that side explicit — which is legal, and is the cost
     * the rule is naming rather than a defect it is asserting.
     */
    public const string DEFAULT_SUFFIX = '_id';

    /**
     * Whether this key is one the rule judges at all.
     *
     * A key with no columns is not a key this reading understood, and reporting it would be a claim
     * about a constraint nobody read. A key with several is deliberately out of scope — see above.
     *
     * @param  list<string>  $columns
     */
    public static function judges(array $columns): bool
    {
        return count($columns) === 1;
    }

    /**
     * Whether this column departs from the convention.
     *
     * The comparison is on the BARE column name. A qualified one would never match a suffix and the
     * rule would report every key on every table — the failure direction that floods a report and
     * gets a convention rule switched off, which is the outcome this package treats as worse than
     * silence.
     */
    public static function violates(string $column, string $suffix): bool
    {
        $bare = self::bareName($column);

        // A column named exactly `_id` satisfies `str_ends_with` and is not what the convention
        // asks for: the suffix is meant to follow the thing being referenced, and on its own it
        // names nothing. Reported rather than passed, because a name that is ONLY the suffix is a
        // stronger sign of a mistake than one that lacks it.
        return $bare === $suffix || ! str_ends_with($bare, $suffix);
    }

    /**
     * Every foreign key on this table, as constraint name => its columns.
     *
     * Read through the same parser the index-coverage rule uses rather than re-split here: the
     * encoding is the catalog's, and a second reader of one format is a second thing to keep in
     * step with it.
     *
     * @return array<string, list<string>>
     */
    public static function keysOf(SchemaObject $table): array
    {
        return ForeignKeyIndexCoverage::parse($table->getString('foreign_keys') ?? '');
    }

    /**
     * Whether this column is one whose intended name the convention can DERIVE.
     *
     * The narrowing that keeps the rule free of false positives, and it was found by the package's
     * own fixtures rather than reasoned out in advance: a single-column foreign key can legitimately
     * reference a NATURAL key, and then `_id` is not the convention at all. `tenant_slug` pointing at
     * `tenants.slug` is named exactly right — it says which column it holds — and a rule demanding
     * `tenant_id` there would report a correct schema.
     *
     * So the rule speaks only where the intended name is unambiguous: the column is the singular of
     * the referenced table, which is precisely the case where Laravel WOULD have derived
     * `<column>_id` and the migration wrote `<column>`. Anywhere else — `owner` referencing `users`,
     * `tenant_slug` referencing `tenants` — the rule would be guessing what the column should have
     * been called, and a convention rule that guesses is one a project switches off.
     *
     * That is a real limit and it is stated rather than hidden: a custom name unrelated to its table
     * goes unreported.
     */
    public static function derivesFrom(string $column, string $referencedTable): bool
    {
        $table = self::bareName($referencedTable);
        $bare = self::bareName($column);

        return $bare !== '' && $table !== '' && self::singular($table) === $bare;
    }

    /**
     * The singular of a table name, for the two shapes Laravel's own pluralizer produces most.
     *
     * Deliberately narrow. A full inflector would let the rule speak about names it half-understands,
     * and the whole point of the narrowing above is to speak only where the answer is not a guess —
     * so a plural this cannot undo means the rule stays quiet, which is the safe direction.
     */
    private static function singular(string $table): string
    {
        if (str_ends_with($table, 'ies')) {
            return substr($table, 0, -3).'y';
        }

        return str_ends_with($table, 's') ? substr($table, 0, -1) : $table;
    }

    /** The last segment of a possibly-qualified name. */
    public static function bareName(string $identifier): string
    {
        $parts = explode('.', $identifier);

        return trim(end($parts), '"`[] ');
    }
}
