<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Understanding;

/**
 * A partial index's `WHERE` clause, read into a shape two of them can be compared in.
 *
 * ## What this does NOT do, stated first because it is the point
 *
 * It answers "are these two predicates the same condition" and nothing else. It does not answer
 * whether one IMPLIES the other, and implication is the hard question a redundancy verdict actually
 * needs — `WHERE deleted_at IS NULL` selects a subset of `WHERE true`, and no amount of comparing
 * text knows that.
 *
 * So **no verdict moves because this class exists**. A partial index is still reported as not
 * compared, by {@see IndexComprehension}, exactly as before. What changes is that the report can now
 * say what KIND of condition went uncompared instead of echoing the server's SQL back at a reader
 * who has already seen it.
 *
 * ## Why equality alone is worth having
 *
 * Two indexes carrying the same condition cover exactly the same rows, so the predicate cancels and
 * the columns decide — the one comparison that follows arithmetically rather than from a heuristic.
 * That is a later slice; this one lays the reading it will need and proves it against real output.
 *
 * ## The forms it knows, every one measured rather than imagined
 *
 * Measured against PostgreSQL 18.0 by creating the index and reading `pg_get_expr(indpred,
 * indrelid)` back — the same expression the PostgreSQL catalog reader stores in an index object's
 * `predicate`. That reader is named in prose rather than as a class reference on purpose: this file
 * stays in the core package and the reader would move to a driver one, so naming it would be the
 * coupling the topology arm refuses. Four kinds, and the surprise is that several of them have TWO
 * spellings for one condition:
 *
 * | written | `pg_get_expr` prints | kind |
 * |---|---|---|
 * | `status <> 'processed'` | `((status)::text <> 'processed'::text)` | inequality |
 * | `is_active = true` | `(is_active = true)` | boolean |
 * | `is_active` | `is_active` | boolean |
 * | `NOT is_active` | `(NOT is_active)` | boolean |
 * | `status = ANY (ARRAY['pending','failed'])` | `((status)::text = ANY (ARRAY['pending'::text, 'failed'::text]))` | set |
 * | `status IN ('pending','failed')` | `((status)::text = ANY ((ARRAY['pending'::character varying, …])::text[]))` | set |
 * | `consumed_at IS NULL` | `(consumed_at IS NULL)` | null |
 *
 * **The last two rows are the reason normalization is not decoration.** `IN (…)` and
 * `= ANY (ARRAY[…])` select identical rows and print differently — different literal casts, and an
 * extra parenthesis layer around the array. Compared as text they are two conditions; compared here
 * they are one. The same holds for `is_active` against `is_active = true`.
 *
 * **`!=` is deliberately not handled, and that is a measurement.** PostgreSQL rewrites it: an index
 * created `WHERE status != 'processed'` prints back with `<>`. A branch for it would be code no
 * server can reach.
 *
 * ## The refusal, and why it is the feature
 *
 * Anything outside those shapes returns null — a compound `AND`/`OR`, a range test, a function call,
 * a comparison against a non-literal. A parser that guessed would produce a confident normal form
 * for a condition it misread, and two indexes would then be called identical on the strength of the
 * misreading. Measured, `WHERE status <> 'processed' AND consumed_at IS NULL` prints as
 * `(((status)::text <> 'processed'::text) AND (consumed_at IS NULL))`, which contains both an
 * inequality and a NULL test as substrings: a reader willing to match loosely would report it as
 * either half and be wrong about which rows the index covers. **The cost of refusing a shape is a
 * vaguer sentence; the cost of guessing is a wrong verdict about which index to drop.**
 */
final readonly class IndexPredicate
{
    /**
     * A column reference as `pg_get_expr` prints one: bare lowercase, or quoted when it is not.
     *
     * The quoted form is kept verbatim including its quotes, because `"Status"` and `status` are
     * different columns and normalizing them together would merge two indexes that are not the same.
     */
    private const string IDENTIFIER = '(?:[a-z_][a-z0-9_]*|"[^"]+")';

    /**
     * The SQL type names that contain a space, listed rather than matched loosely.
     *
     * A pattern like `[a-z ]+` after `::` would swallow a following ` AND` — under `/i` the keyword
     * is just more letters — and the compound predicate that refusal exists for would turn into
     * whichever half survived. An explicit list cannot do that.
     */
    private const string MULTI_WORD_TYPES = 'character varying|bit varying|double precision|(?:timestamp|time) with(?:out)? time zone';

    private function __construct(
        /** The condition in a spelling two predicates can be compared in. */
        public string $normalized,
        /** What kind of condition it is: `inequality`, `boolean`, `set` or `null`. */
        public string $kind,
        /** The column the condition is about, as the server spells it. */
        public string $column,
    ) {}

    /**
     * Read one `pg_get_expr` predicate, or null when its shape is not one of the four.
     */
    public static function parse(string $predicate): ?self
    {
        $bare = self::withoutCasts($predicate);
        $ident = self::IDENTIFIER;

        // The NULL test first: it carries no operator the other arms look for, and testing it later
        // would mean each of them had to exclude the word NULL by hand.
        if (preg_match('/^\(?('.$ident.')\s+IS\s+(NOT\s+)?NULL\)?$/i', $bare, $m) === 1) {
            $not = ($m[2] ?? '') !== '' ? ' NOT' : '';

            return new self($m[1].' IS'.$not.' NULL', 'null', $m[1]);
        }

        // `WHERE is_active` and `WHERE NOT is_active` — a boolean column used as the condition
        // itself. Normalized onto the `= true` / `= false` spelling so the two reach one form.
        if (preg_match('/^\(?(NOT\s+)?('.$ident.')\)?$/i', $bare, $m) === 1) {
            // No `??` on this group although the arm above needs one: an optional group that is
            // FOLLOWED by a participating group is filled with the empty string, while a trailing
            // one is simply omitted. Same syntax, two behaviors — and PHPStan reads the difference.
            $value = $m[1] !== '' ? 'false' : 'true';

            return new self($m[2].' = '.$value, 'boolean', $m[2]);
        }

        if (preg_match('/^\(?('.$ident.')\s*=\s*(true|false)\)?$/i', $bare, $m) === 1) {
            return new self($m[1].' = '.strtolower($m[2]), 'boolean', $m[1]);
        }

        // `\(+` and `\)+` rather than one each: `IN (…)` prints an extra parenthesis layer around
        // the array that `= ANY (ARRAY[…])` does not, and the two mean the same thing.
        if (preg_match('/^\(?\s*('.$ident.')\s*=\s*ANY\s*\(+\s*ARRAY\[(.+?)\]\s*\)+$/is', $bare, $m) === 1) {
            $values = self::sortedLiterals($m[2]);

            return $values === null
                ? null
                : new self($m[1].' = ANY (ARRAY['.implode(', ', $values).'])', 'set', $m[1]);
        }

        // Inequality LAST: nothing above can reach it, and putting it first would cost a reader a
        // second of wondering whether `<>` could shadow the `=` forms.
        if (preg_match('/^\(?('.$ident.")\s*<>\s*('[^']*')\)?$/i", $bare, $m) === 1) {
            return new self($m[1].' <> '.$m[2], 'inequality', $m[1]);
        }

        return null;
    }

    /**
     * The condition as a reader wants to hear it, rather than as the server spells it.
     *
     * No backticks and no markup: this sentence reaches a terminal line and a JSON skip detail, and
     * neither renders them.
     */
    public function describe(): string
    {
        return match ($this->kind) {
            'null' => str_contains($this->normalized, 'IS NOT NULL')
                ? sprintf('the rows where %s is set', $this->column)
                : sprintf('the rows where %s is null', $this->column),
            'boolean' => sprintf('the rows where %s is %s', $this->column, str_ends_with($this->normalized, 'true') ? 'true' : 'false'),
            'set' => sprintf('the rows whose %s is one of a fixed set', $this->column),
            default => sprintf('the rows whose %s differs from one value', $this->column),
        };
    }

    /**
     * The predicate with PostgreSQL's casts and its redundant parentheses removed.
     *
     * `pg_get_expr` prints a cast on nearly every column reference and literal — `(status)::text`,
     * `'processed'::text`, and `::sqlens.job_state` when the type is not in `search_path` — and the
     * same condition acquires or loses them with the column's declared type. Two predicates that
     * mean the same thing have to normalize the same way, so the casts go before anything matches.
     */
    private static function withoutCasts(string $predicate): string
    {
        $type = '(?:'.self::MULTI_WORD_TYPES.'|(?:[a-z_][a-z0-9_]*\.)?(?:[a-z_][a-z0-9_]*|"[^"]+"))';

        $bare = preg_replace('/::\s*'.$type.'(\[\])?/i', '', $predicate) ?? $predicate;

        // A parenthesized bare column reference: `(status)` -> `status`. Only a plain identifier,
        // never an expression — `(a + b)` keeps its parentheses, because dropping them would change
        // what the text says.
        //
        // The lookbehind is not tidiness, it is the difference between a refusal and a wrong answer:
        // without it `lower(email)` loses the parentheses around its ARGUMENT and becomes the single
        // identifier `loweremail`, which the boolean arm below then reads as `loweremail = true`.
        // Measured — that is a confident reading of a function call as a column, and the arm named
        // "does not read a bare identifier out of a shape it refused" is what found it.
        return trim(preg_replace('/(?<![a-z0-9_"])\(\s*('.self::IDENTIFIER.')\s*\)/i', '$1', $bare) ?? $bare);
    }

    /**
     * The quoted literals of an `ARRAY[…]`, sorted — or null when one of them is not a literal.
     *
     * Sorted because a set has no order: `ARRAY['a','b']` and `ARRAY['b','a']` select the same rows,
     * and a comparison that said otherwise would report two identical indexes as different. Null on
     * anything that is not a plain quoted literal, for the reason in the class docblock — a refusal
     * costs a vague sentence, a guess costs a wrong verdict.
     *
     * There is deliberately no empty-array branch: the caller's pattern requires at least one
     * character between the brackets, and `explode()` never returns an empty array, so the check
     * would be a line no run can reach — which the coverage floor reports rather than tolerates.
     *
     * @return list<string>|null
     */
    private static function sortedLiterals(string $inner): ?array
    {
        $literals = [];

        foreach (array_map(trim(...), explode(',', $inner)) as $part) {
            if (preg_match("/^'[^']*'$/", $part) !== 1) {
                return null;
            }

            $literals[] = $part;
        }

        sort($literals, SORT_STRING);

        return $literals;
    }
}
