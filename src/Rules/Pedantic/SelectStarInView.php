<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Pedantic;

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
     * Every star reference in the outer select list, in the order they appear.
     *
     * @return list<string> `*` for a bare star, `alias.*` for a qualified one; empty when the
     *                      statement is not a view definition or its select list names its columns
     */
    public static function stars(string $canonical): array
    {
        if (! self::isViewDefinition($canonical)) {
            return [];
        }

        $list = self::selectList($canonical);

        if ($list === null) {
            return [];
        }

        return self::starsIn($list);
    }

    /**
     * The outer select list: from after the definition's `SELECT` to its own `FROM`.
     *
     * Returns null when there is no such list to read — a view defined through a `VALUES` clause, a
     * `TABLE t` shorthand, or a statement this scan cannot follow. Null is not "no stars": the
     * caller must not turn it into a pass, which is why it is a distinct answer rather than an
     * empty array.
     */
    public static function selectList(string $canonical): ?string
    {
        $start = self::outerSelectOffset($canonical);

        if ($start === null) {
            return null;
        }

        $depth = 0;
        $length = strlen($canonical);
        $offset = $start;

        while ($offset < $length) {
            $char = $canonical[$offset];

            if (in_array($char, ["'", '"', '`'], true)) {
                $offset = self::skipQuoted($canonical, $offset);

                continue;
            }

            if ($char === '(') {
                $depth++;
                $offset++;

                continue;
            }

            if ($char === ')') {
                // A closing parenthesis at depth zero ends the definition itself — `CREATE VIEW v AS
                // (SELECT …)`. The list ends here for the same reason a FROM would end it.
                if ($depth === 0) {
                    return substr($canonical, $start, $offset - $start);
                }

                $depth--;
                $offset++;

                continue;
            }

            if ($depth === 0 && self::keywordAt($canonical, $offset, 'FROM')) {
                return substr($canonical, $start, $offset - $start);
            }

            $offset++;
        }

        // No FROM at all is still a select list — `CREATE VIEW v AS SELECT 1`. Returning it rather
        // than null keeps a constant view from being reported as unreadable.
        return substr($canonical, $start);
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

        if (preg_match('/([A-Za-z_][A-Za-z0-9_$]*|"[^"]*"|`[^`]*`)\.$/', $before, $matches) !== 1) {
            return null;
        }

        return trim($matches[1], '"`');
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
     * The offset just past the quoted run starting at `$offset`.
     *
     * A doubled quote inside a run is an escaped quote in both engines' default modes, so the run
     * continues — the case that decides whether `'it''s *'` is read as one literal or as two with a
     * bare star between them.
     */
    private static function skipQuoted(string $subject, int $offset): int
    {
        $quote = $subject[$offset];
        $length = strlen($subject);
        $offset++;

        while ($offset < $length) {
            if ($subject[$offset] === '\\' && $quote === "'") {
                $offset += 2;

                continue;
            }

            if ($subject[$offset] === $quote) {
                if (substr($subject, $offset + 1, 1) === $quote) {
                    $offset += 2;

                    continue;
                }

                return $offset + 1;
            }

            $offset++;
        }

        return $length;
    }
}
