<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\Support;

use Pushery\SQLens\Canonical\StatementAction;
use Pushery\SQLens\Canonical\StringLiteralMask;
use Pushery\SQLens\Drivers\Mysql\Canonical\MysqlCanonicalization;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

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
     * The redefinition a statement performs on the column it is about, or null when it performs none.
     *
     * One `ALTER TABLE` can redefine several columns, `MODIFY a INT, MODIFY b ENUM('x')`, and each of
     * its actions reaches a rule as a subject of its own, naming its own column over the statement's
     * whole text ({@see StatementAction}). So the clause is looked up by that column. Read from the
     * front instead, every question about `b` would be answered with what the statement does to `a`,
     * and a redefinition behind an `ADD COLUMN` would not be found at all.
     */
    public static function of(MigrationStatementView $statement): ?self
    {
        return self::parse($statement->canonical, $statement->soleTarget(SchemaObjectType::Column)?->qualifiedName());
    }

    /**
     * Read a canonical statement as a column redefinition, or null when it is not one.
     *
     * With a column, the redefinition of that column, wherever it stands in the action list; a
     * `CHANGE` is found by the name it renames. Without one, the first redefinition the list holds.
     *
     * Both spellings are read the same way, deliberately. `MODIFY` is what Laravel's grammar
     * emits for `->change()`; `CHANGE` additionally renames and reaches SQLens only through a raw
     * statement. The rename is not what makes either of them expensive — the redefinition beside
     * it is — so telling them apart here would only invite a second, near-identical treatment.
     */
    public static function parse(string $canonical, ?string $column = null): ?self
    {
        // The leading `ALTER TABLE <table>` is matched but not captured — which table this is
        // belongs to the classified targets, not to a text match.
        if (preg_match('/^ALTER TABLE \S+ (?<actions>\S.*)$/', $canonical, $statement) !== 1) {
            return null;
        }

        // String literals are masked before anything is read. The canonicalization leaves literal
        // CONTENT untouched by design, since inside quotes a keyword is data, not syntax, so a
        // member list `ENUM('a, b')` would otherwise end an action at its comma, and a default of
        // `'FIRST'` would read as a position clause. Nothing read here lives inside a literal: a
        // name, the head of a type, a position clause.
        $actions = StringLiteralMask::forDriver(new MysqlCanonicalization)->apply($statement['actions']);

        foreach (self::actionsIn($actions) as $action) {
            // `MODIFY [COLUMN] <col> <definition>` and `CHANGE [COLUMN] <old> <new> <definition>`:
            // one alternation rather than two passes, so the two spellings cannot drift into two
            // behaviors. `COLUMN` is the manual's optional word, and it cannot be a column's name
            // here: a column named `column` keeps its quotes in the canonical form.
            $matched = preg_match(
                '/^(?:MODIFY (?:COLUMN )?(?<modified>\S+)|CHANGE (?:COLUMN )?(?<old>\S+) (?<renamed>\S+)) (?<definition>\S.*)$/',
                $action,
                $matches,
            );

            if ($matched !== 1) {
                continue;
            }

            $named = $matches['modified'] === '' ? $matches['old'] : $matches['modified'];

            if ($column !== null && $named !== $column) {
                continue;
            }

            return new self(
                column: $matches['modified'] === '' ? $matches['renamed'] : $matches['modified'],
                typeName: self::typeNameOf($matches['definition']),
                positioned: self::hasPositionClause($matches['definition']),
            );
        }

        return null;
    }

    /**
     * The actions of a masked action list, cut at the commas on the statement's own level.
     *
     * A comma inside parentheses belongs to a type, `DECIMAL(10, 2)`, and one inside backticks to a
     * name; neither ends an action. Literals arrive masked, so their commas are already gone.
     *
     * @return list<string>
     */
    private static function actionsIn(string $masked): array
    {
        $actions = [];
        $depth = 0;
        $quoted = false;
        $start = 0;
        $length = strlen($masked);

        for ($offset = 0; $offset < $length; $offset++) {
            $character = $masked[$offset];

            if ($character === '`') {
                $quoted = ! $quoted;
            } elseif ($quoted) {
                continue;
            } elseif ($character === '(') {
                $depth++;
            } elseif ($character === ')') {
                $depth = max(0, $depth - 1);
            } elseif ($character === ',' && $depth === 0) {
                $actions[] = trim(substr($masked, $start, $offset - $start));
                $start = $offset + 1;
            }
        }

        $actions[] = trim(substr($masked, $start));

        return $actions;
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
     * The definition is one action's and arrives with its literals masked ({@see self::parse()}),
     * so a default of `'FIRST'` or `'AFTER x'` cannot read as a positioned redefinition, and the
     * position clause of the action after it cannot either.
     */
    private static function hasPositionClause(string $definition): bool
    {
        return preg_match('/\s(?:AFTER\s+\S+|FIRST)\s*$/', $definition) === 1;
    }
}
