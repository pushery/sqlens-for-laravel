<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Pedantic;

use Pushery\SQLens\Canonical\StringLiteralMask;
use Pushery\SQLens\Contracts\DriverCanonicalization;

/**
 * Whether a view's DDL selects `*`, and which reference does it.
 *
 * ## The trap, measured on both engines
 *
 * A view's column list is fixed when the view is CREATED. Against PostgreSQL 18.4 and MySQL 8.4.10,
 * with a two-column table and a view over `SELECT *`:
 *
 * ```
 * PG   pg_get_viewdef            →  SELECT a, b FROM t
 * MY   VIEWS.VIEW_DEFINITION     →  select `t`.`a` AS `a`, `t`.`b` AS `b` from `t`
 * ```
 *
 * Then `ALTER TABLE t ADD COLUMN c` — and both re-read the same way: still `a, b`. The view does
 * not grow. It has to be REPLACED, and nothing about the added column says so. That is why this is
 * a rule and not a style note: the failure arrives months after the migration that caused it, in a
 * report whose new column is simply absent.
 *
 * ## Why this reads the SELECT LIST and nothing else
 *
 * `*` appears in SQL in four shapes and only one of them is this trap:
 *
 * | shape | example | expands into the view's column list? |
 * |---|---|---|
 * | select-list star | `SELECT * FROM t` | **yes** |
 * | qualified star | `SELECT t.* , x FROM t` | **yes** |
 * | aggregate star | `SELECT count(*) FROM t` | no — it is an argument |
 * | multiplication | `SELECT price * qty FROM t` | no — it is an operator |
 *
 * A subquery's star is a fifth: `WHERE EXISTS (SELECT * FROM u)` never reaches the view's column
 * list either, so reporting it would be a false positive on a perfectly safe view.
 *
 * So the scan is bounded to the OUTER select list — everything between the top-level `SELECT` and
 * its matching `FROM` — at parenthesis depth zero. That single boundary rules out the aggregate
 * (inside a function's parentheses) and the subquery (inside its own) without a special case for
 * either, and multiplication is ruled out by what may stand before a star.
 *
 * ## It walks characters, not a regular expression
 *
 * A pattern cannot count parentheses, and every discrimination above is a counting question. It
 * also has to ignore what is inside a string literal — `SELECT '*' AS marker` is not a star — and a
 * pattern that tried would need to know where literals begin, which is the same counting problem.
 *
 * Where a literal ends is the driver's to say: on PostgreSQL `'\'` is a whole literal, on MySQL it
 * is an escaped quote that runs on. So the definition is masked with the driver's
 * {@see StringLiteralMask} before it is read, and every literal is empty by the time a star is
 * looked for.
 *
 * ## Every branch of a set operation
 *
 * `SELECT a FROM t UNION ALL SELECT * FROM u` freezes the columns of `u` exactly as a single select
 * would. So the lists of the branches joined by `UNION`, `INTERSECT` or `EXCEPT` at depth zero are
 * read as well, and a branch that is not a `SELECT` (`TABLE u`, `VALUES …`) makes the definition one
 * this scan cannot read rather than one it read as clean.
 */
final readonly class SelectStarInView
{
    /**
     * Whether this statement creates a view.
     *
     * Both engines allow clauses between `CREATE` and `VIEW` that the other does not — MySQL's
     * `ALGORITHM`, `DEFINER` and `SQL SECURITY`, PostgreSQL's `MATERIALIZED` and `RECURSIVE`. Rather
     * than enumerate them per engine, the check is that `VIEW` appears as a KEYWORD before the
     * definition's `AS`: everything in between is a modifier by construction, whichever engine
     * spelled it.
     */
    public static function isViewDefinition(string $canonical): bool
    {
        return preg_match('/^\s*CREATE\b[^;]*?\bVIEW\b/i', $canonical) === 1;
    }

    /**
     * Every star reference in the outer select list and in the lists of the branches joined to it,
     * in the order they appear.
     *
     * @return list<string> `*` for a bare star, `alias.*` for a qualified one; empty when the
     *                      statement is not a view definition or its select lists name their columns
     */
    public static function stars(string $canonical, DriverCanonicalization $syntax): array
    {
        if (! self::isViewDefinition($canonical)) {
            return [];
        }

        $found = [];

        foreach (self::selectLists(StringLiteralMask::forDriver($syntax)->apply($canonical)) ?? [] as $list) {
            array_push($found, ...self::starsIn($list));
        }

        return $found;
    }

    /**
     * The outer select list: from after the definition's `SELECT` to its own `FROM`, with every
     * string literal emptied.
     *
     * Returns null when there is no such list to read — a view defined through a `VALUES` clause, a
     * `TABLE t` shorthand, a set operation one of whose branches is such a form, or a statement this
     * scan cannot follow. Null is not "no stars": the caller must not turn it into a pass, which is
     * why it is a distinct answer rather than an empty array.
     */
    public static function selectList(string $canonical, DriverCanonicalization $syntax): ?string
    {
        return (self::selectLists(StringLiteralMask::forDriver($syntax)->apply($canonical)) ?? [])[0] ?? null;
    }

    /**
     * The definition's select list followed by the list of every branch a set operation joins to it
     * at depth zero, or null when one of them cannot be read.
     *
     * @return list<string>|null
     */
    private static function selectLists(string $sql): ?array
    {
        $start = self::outerSelectOffset($sql);

        if ($start === null) {
            return null;
        }

        [$list, $end] = self::listFrom($sql, $start);
        $lists = [$list];

        while ($end !== null) {
            $operator = self::nextSetOperator($sql, $end);

            if ($operator === null) {
                break;
            }

            $start = self::branchSelect($sql, $operator);

            if ($start === null) {
                return null;
            }

            [$list, $end] = self::listFrom($sql, $start);
            $lists[] = $list;
        }

        return $lists;
    }

    /**
     * One select list from `$start` and the offset where it stopped: at its own `FROM`, at a set
     * operator, or at a closing parenthesis at depth zero. A list that runs to the end of the
     * statement comes back with null.
     *
     * @return array{string, int|null}
     */
    private static function listFrom(string $sql, int $start): array
    {
        $depth = 0;
        $length = strlen($sql);
        $offset = $start;

        while ($offset < $length) {
            $char = $sql[$offset];

            if (in_array($char, ["'", '"', '`'], true)) {
                $offset = self::skipQuoted($sql, $offset);

                continue;
            }

            if ($char === '(') {
                $depth++;
                $offset++;

                continue;
            }

            if ($char === ')') {
                // A closing parenthesis at depth zero ends the definition itself — `CREATE VIEW v AS
                // (SELECT …)` — or a branch of it. The list ends here for the same reason a FROM
                // would end it.
                if ($depth === 0) {
                    return [substr($sql, $start, $offset - $start), $offset];
                }

                $depth--;
                $offset++;

                continue;
            }

            if ($depth === 0 && (self::keywordAt($sql, $offset, 'FROM') || self::setOperatorAt($sql, $offset) !== null)) {
                return [substr($sql, $start, $offset - $start), $offset];
            }

            $offset++;
        }

        // No FROM at all is still a select list — `CREATE VIEW v AS SELECT 1`. Returning it rather
        // than null keeps a constant view from being reported as unreadable.
        return [substr($sql, $start), null];
    }

    /**
     * The offset just past the next set operator at depth zero from `$offset`, or null when the
     * definition joins no further branch.
     *
     * A closing parenthesis at depth zero closes a branch, or the definition, that was opened before
     * `$offset`; what may follow it is the next operator, so the scan goes on.
     */
    private static function nextSetOperator(string $sql, int $offset): ?int
    {
        $depth = 0;
        $length = strlen($sql);

        while ($offset < $length) {
            $char = $sql[$offset];

            if (in_array($char, ["'", '"', '`'], true)) {
                $offset = self::skipQuoted($sql, $offset);

                continue;
            }

            if ($char === '(' || $char === ')') {
                $depth = max(0, $depth + ($char === '(' ? 1 : -1));
                $offset++;

                continue;
            }

            $operator = $depth === 0 ? self::setOperatorAt($sql, $offset) : null;

            if ($operator !== null) {
                return $offset + strlen($operator);
            }

            $offset++;
        }

        return null;
    }

    /**
     * The offset just past the `SELECT` of the branch after a set operator, or null when the branch
     * is not a select: `UNION TABLE u` or `UNION VALUES …` holds no list this scan can read.
     *
     * The operator's own quantifier (`ALL`, `DISTINCT`) and the parentheses a branch may stand in
     * come first.
     */
    private static function branchSelect(string $sql, int $offset): ?int
    {
        if (preg_match('/\G\s*(?:(?:ALL|DISTINCT)\b\s*)?(?:\(\s*)*SELECT\b/i', $sql, $matches, 0, $offset) !== 1) {
            return null;
        }

        return $offset + strlen($matches[0]);
    }

    /** The set operator standing at `$offset` as a whole word, or null. */
    private static function setOperatorAt(string $sql, int $offset): ?string
    {
        foreach (['UNION', 'INTERSECT', 'EXCEPT'] as $operator) {
            if (self::keywordAt($sql, $offset, $operator)) {
                return $operator;
            }
        }

        return null;
    }

    /**
     * Where the view definition's own `SELECT` ends, or null if there is none at depth zero.
     *
     * The `SELECT` has to be the definition's, not one from a `WITH` clause's common table
     * expression — which is why it is found by scanning at depth zero rather than by searching for
     * the first occurrence. A `WITH` body sits inside parentheses, so depth alone separates them.
     */
    private static function outerSelectOffset(string $canonical): ?int
    {
        $depth = 0;
        $length = strlen($canonical);
        $offset = 0;
        $seenAs = false;
        $afterAs = null;

        while ($offset < $length) {
            $char = $canonical[$offset];

            if (in_array($char, ["'", '"', '`'], true)) {
                $offset = self::skipQuoted($canonical, $offset);

                continue;
            }

            if ($char === '(') {
                // The one parenthesis that is NOT a nesting level: `CREATE VIEW v AS (SELECT …)`
                // wraps the definition itself, so counting it would put the definition's own SELECT
                // at depth 1 and hide it — measured, this arm was red before the exception existed.
                //
                // It must IMMEDIATELY follow the `AS`, and that is the second measurement: a `WITH`
                // clause spells `recent AS (SELECT …)`, whose parenthesis also stands after an `AS`
                // and is a real nesting level. Accepting any post-`AS` parenthesis turned the CTE
                // arm red, which is how the rule would have started reporting a subquery's star.
                if ($afterAs !== null && trim(substr($canonical, $afterAs, $offset - $afterAs)) === '') {
                    $afterAs = null;
                    $offset++;

                    continue;
                }

                $depth++;
                $offset++;

                continue;
            }

            if ($char === ')') {
                $depth = max(0, $depth - 1);
                $offset++;

                continue;
            }

            if ($depth === 0 && ! $seenAs && self::keywordAt($canonical, $offset, 'AS')) {
                // `AS` also introduces a column alias list before the definition —
                // `CREATE VIEW v (a, b) AS SELECT …` — but that one is inside parentheses, so the
                // first depth-zero `AS` is the definition's every time.
                $seenAs = true;
                $offset += 2;
                $afterAs = $offset;

                continue;
            }

            if ($depth === 0 && $seenAs && self::keywordAt($canonical, $offset, 'SELECT')) {
                return $offset + 6;
            }

            $offset++;
        }

        return null;
    }

    /**
     * The stars in one select list, at depth zero.
     *
     * A star counts when what stands before it is the start of the list, a comma, a set-quantifier
     * keyword, or `<identifier>.`. Anything else before a star is an operand, which makes the star
     * multiplication — the one shape that looks identical and means the opposite.
     *
     * @return list<string>
     */
    private static function starsIn(string $list): array
    {
        $found = [];
        $depth = 0;
        $length = strlen($list);
        $offset = 0;

        while ($offset < $length) {
            $char = $list[$offset];

            if (in_array($char, ["'", '"', '`'], true)) {
                $offset = self::skipQuoted($list, $offset);

                continue;
            }

            if ($char === '(') {
                $depth++;
                $offset++;

                continue;
            }

            if ($char === ')') {
                $depth = max(0, $depth - 1);
                $offset++;

                continue;
            }

            if ($char !== '*' || $depth !== 0) {
                $offset++;

                continue;
            }

            $before = rtrim(substr($list, 0, $offset));
            $qualifier = self::qualifierBefore($before);

            if ($qualifier !== null) {
                $found[] = $qualifier.'.*';
                $offset++;

                continue;
            }

            if ($before === '' || str_ends_with($before, ',') || self::endsWithSetQuantifier($before)) {
                $found[] = '*';
            }

            $offset++;
        }

        return $found;
    }

    /** The `t` of a `t.*`, or null when the star is not qualified by an identifier. */
    private static function qualifierBefore(string $before): ?string
    {
        if (! str_ends_with($before, '.')) {
            return null;
        }

        if (preg_match('/([A-Za-z_][A-Za-z0-9_$]*|"(?:[^"]|"")*"|`(?:[^`]|``)*`)\.$/', $before, $matches) !== 1) {
            return null;
        }

        $name = $matches[1];

        if ($name[0] !== '"' && $name[0] !== '`') {
            return $name;
        }

        // A quoted name keeps its one escape, a doubled quote, as the single quote it stands for.
        return str_replace($name[0].$name[0], $name[0], substr($name, 1, -1));
    }

    /**
     * Whether the text before a star is `DISTINCT` or `ALL`.
     *
     * `SELECT DISTINCT * FROM t` is the same expansion as `SELECT * FROM t`. Without this the rule
     * would be silent on it and — worse — silent for a reason nobody could see in its output.
     */
    private static function endsWithSetQuantifier(string $before): bool
    {
        return preg_match('/\b(DISTINCT|ALL)$/i', $before) === 1;
    }

    /** Whether `$word` stands at `$offset` as a whole word. */
    private static function keywordAt(string $subject, int $offset, string $word): bool
    {
        $length = strlen($word);

        if (strcasecmp(substr($subject, $offset, $length), $word) !== 0) {
            return false;
        }

        $before = $offset === 0 ? '' : $subject[$offset - 1];
        $after = substr($subject, $offset + $length, 1);

        return ! self::isWordCharacter($before) && ! self::isWordCharacter($after);
    }

    private static function isWordCharacter(string $char): bool
    {
        return $char !== '' && (ctype_alnum($char) || $char === '_' || $char === '$');
    }

    /**
     * The offset just past the quoted run starting at `$offset`, or the end of the subject when the
     * run is never closed.
     *
     * The definition is masked before it is read, so a string literal is empty here and the run that
     * carries content is a quoted identifier. Its one escape, a doubled quote, needs no branch of its
     * own: the first quote ends this run and the second opens the next at once, with nothing between
     * them. `"it""s *"` is therefore read as two adjacent runs that cover exactly the characters one
     * run would, and the star inside the name is never read as a bare one.
     */
    private static function skipQuoted(string $subject, int $offset): int
    {
        $close = strpos($subject, $subject[$offset], $offset + 1);

        return $close === false ? strlen($subject) : $close + 1;
    }
}
