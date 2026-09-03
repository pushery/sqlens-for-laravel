<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\Support;

/**
 * What a canonical `ALTER TABLE … MODIFY` / `… CHANGE` says about the column it redefines —
 * and, just as importantly, what it does not say.
 *
 * MySQL's redefinition syntax takes the column's WHOLE definition, never a delta. `MODIFY col
 * BIGINT NOT NULL` is what you write to change the type, and it is also what you write to flip
 * the nullability, to move the column, or to change nothing at all. Which of those it turns out
 * to be depends on the column's CURRENT definition, which is not in the migration. That is the
 * honesty boundary every rule reading this form has to respect, and stating it here — once —
 * keeps it out of the rules.
 *
 * What the statement DOES settle is small and worth having:
 *
 * - the TYPE NAME the column ends up with, which decides whether MySQL has a non-rebuilding path
 *   at all (VARCHAR does, and only VARCHAR — {@see self::$typeName});
 * - whether the statement carries a POSITION clause (`AFTER x` / `FIRST`), which is the one
 *   operation the SQL names outright.
 *
 * Everything else — is this a widening or a narrowing, was the column nullable before — needs a
 * reading of the live catalog, which the lint suite deliberately does not take.
 *
 * ## Why it parses the CANONICAL form and not the grammar output
 *
 * The canonicalization has already normalized identifier quoting and folded keyword casing, so
 * `VARCHAR` is `VARCHAR` however the migration spelled it, and a column actually NAMED `varchar`
 * is quoted and cannot be mistaken for the type. Matching Laravel's raw grammar instead would
 * make this break the day the framework changes a space.
 */
final readonly class ColumnRedefinition
{
    private function __construct(
        /** The redefined column's name, as it appears in the canonical statement. */
        public string $column,
        /**
         * The bare type NAME the column is redefined to — `VARCHAR`, `BIGINT`, `ENUM` — without
         * its length, precision or member list. Uppercase, because the canonicalization already
         * folded it and this reads it rather than re-deriving it.
         */
        public string $typeName,
        /**
         * Whether the statement carries `AFTER <column>` or `FIRST`.
         *
         * The one operation the syntax names outright: without a position clause the column keeps
         * its place, so a reorder is off the table; with one, a reorder is what the statement
         * asked for. It never REMOVES a possibility — a positioned redefinition can still change
         * the type as well — so it only ever widens the set of operations in play.
         */
        public bool $positioned,
    ) {}

    /**
     * Read a canonical statement as a column redefinition, or null when it is not one.
     *
     * Both spellings are read the same way, deliberately. `MODIFY` is what Laravel's grammar
     * emits for `->change()`; `CHANGE` additionally renames and reaches SQLens only through a raw
     * statement. The rename is not what makes either of them expensive — the redefinition beside
     * it is — so telling them apart here would only invite a second, near-identical treatment.
     */
    public static function parse(string $canonical): ?self
    {
        // `MODIFY <col> <definition>` and `CHANGE <old> <new> <definition>`: one alternation
        // rather than two passes, so the two spellings cannot drift into two behaviors. The
        // leading `ALTER TABLE <table>` is matched but not captured — which table this is
        // belongs to the classified targets, not to a text match.
        $matched = preg_match(
            '/^ALTER TABLE \S+ (?:MODIFY (?<modified>\S+)|CHANGE \S+ (?<renamed>\S+)) (?<definition>\S.*)$/',
            $canonical,
            $matches,
        );

        if ($matched !== 1) {
            return null;
        }

        $column = $matches['modified'] === '' ? $matches['renamed'] : $matches['modified'];
        $definition = $matches['definition'];

        return new self(
            column: $column,
            typeName: self::typeNameOf($definition),
            positioned: self::hasPositionClause($definition),
        );
    }

    /** Whether the target type is a VARCHAR — the only type MySQL can resize without a rebuild. */
    public function isVarchar(): bool
    {
        return $this->typeName === 'VARCHAR';
    }

    /**
     * Whether the target type is an enumerated one.
     *
     * ENUM and SET have their own online-DDL story (appending a member at the end is instant,
     * inserting one in the middle is a COPY — measured on MySQL 8.4), and their own rule. This
     * predicate exists so the type-change rule can hand them over rather than answer for them.
     */
    public function isEnumerated(): bool
    {
        return $this->typeName === 'ENUM' || $this->typeName === 'SET';
    }

    /**
     * The bare type name at the head of a column definition.
     *
     * The definition begins with the type and may carry a length, a precision or a member list
     * (`VARCHAR(100)`, `DECIMAL(10, 2)`, `ENUM('a', 'b')`), then attributes. Only the head word
     * is wanted, so the first `(` or space ends it.
     */
    private static function typeNameOf(string $definition): string
    {
        return preg_match('/^([A-Za-z_]+)/', $definition, $matches) === 1 ? strtoupper($matches[1]) : '';
    }

    /**
     * Whether the definition ends in `AFTER <column>` or `FIRST`.
     *
     * String literals are masked out first, and that is not caution for its own sake: a column
     * whose default is `'FIRST'` or `'AFTER x'` would otherwise read as a positioned redefinition,
     * because the canonicalization leaves literal CONTENT untouched by design — inside quotes a
     * keyword is data, not syntax. Masking makes the scan look at the syntax only.
     */
    private static function hasPositionClause(string $definition): bool
    {
        $withoutLiterals = preg_replace("/'(?:[^']|'')*'/", "''", $definition) ?? $definition;

        return preg_match('/\s(?:AFTER\s+\S+|FIRST)\s*$/', $withoutLiterals) === 1;
    }
}
