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
 * coupling the topology arm refuses. Seven kinds, and the surprise is that several of them have TWO
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
 * | `status = 'live'` | `((status)::text = 'live'::text)` | equality |
 * | `status IN ('live')` | `((status)::text = 'live'::text)` | equality |
 * | `status NOT IN ('pending','failed')` | `((status)::text <> ALL ((ARRAY['pending'::character varying, …])::text[]))` | exclusion |
 * | `is_active AND notes IS NULL` | `(is_active AND (notes IS NULL))` | conjunction |
 *
 * **The two set rows are the reason normalization is not decoration.** `IN (…)` and
 * `= ANY (ARRAY[…])` select identical rows and print differently — different literal casts, and an
 * extra parenthesis layer around the array. Compared as text they are two conditions; compared here
 * they are one. The same holds for `is_active` against `is_active = true`.
 *
 * **`!=` is deliberately not handled, and that is a measurement.** PostgreSQL rewrites it: an index
 * created `WHERE status != 'processed'` prints back with `<>`. A branch for it would be code no
 * server can reach. The same holds for a one-member `IN` list, which the server prints as the plain
 * equality above; only `= ANY (ARRAY['live'])` keeps its array, and it reads as that equality too.
 *
 * **An `AND` is read as the set of its parts, and only whole.** The server flattens a nested
 * conjunction into one level, so `(is_active AND notes IS NULL) AND consumed_at IS NULL` prints with
 * three parts side by side and a part is never a conjunction itself. The parts are ordered by their
 * normal form, so `notes IS NULL AND is_active` groups with `is_active AND notes IS NULL`, and a part
 * written twice counts once.
 *
 * ## The refusal, and why it is the feature
 *
 * Anything outside those shapes returns null — an `OR`, a range test, a function call, a comparison
 * against a non-literal, and an `AND` with any such part. A parser that guessed would produce a
 * confident normal form for a condition it misread, and two indexes would then be called identical on
 * the strength of the misreading. Measured, `WHERE status <> 'processed' AND consumed_at IS NULL`
 * prints as `(((status)::text <> 'processed'::text) AND (consumed_at IS NULL))`, which contains both
 * an inequality and a NULL test as substrings: a reader willing to match loosely would report it as
 * either half and be wrong about which rows the index covers. It is read as both halves at once, and
 * an `AND` with one part this class does not know is refused whole, because the parts it could read
 * describe more rows than the index covers. **The cost of refusing a shape is a vaguer sentence; the
 * cost of guessing is a wrong verdict about which index to drop.**
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
     * A quoted literal as `pg_get_expr` prints one, a doubled quote inside it included.
     *
     * `'it''s'` is one literal. A pattern that stopped at the first quote would find `'it'` followed by
     * `'s'`, and the anchored arms below would refuse a condition they know.
     */
    private const string LITERAL = "'(?:[^']|'')*'";

    /**
     * The SQL type names that contain a space, listed rather than matched loosely.
     *
     * A pattern like `[a-z ]+` after `::` would swallow a following ` AND` — under `/i` the keyword
     * is just more letters — and the compound predicate that refusal exists for would turn into
     * whichever half survived. An explicit list cannot do that.
     */
    private const string MULTI_WORD_TYPES = 'character varying|bit varying|double precision|(?:timestamp|time) with(?:out)? time zone';

    /**
     * @param  list<self>  $parts  the conditions a conjunction holds, in normal-form order; empty for every other kind
     */
    private function __construct(
        /** The condition in a spelling two predicates can be compared in. */
        public string $normalized,
        /** What kind of condition it is: `null`, `boolean`, `equality`, `inequality`, `set`, `exclusion` or `conjunction`. */
        public string $kind,
        /** The column the condition is about, as the server spells it; for a conjunction, each column its parts name. */
        public string $column,
        private array $parts = [],
    ) {}

    /**
     * Read one `pg_get_expr` predicate, or null when its shape is not one of the seven.
     */
    public static function parse(string $predicate): ?self
    {
        $bare = self::withoutCasts($predicate);
        $conjuncts = self::conjuncts($bare);

        return $conjuncts === null ? self::single($bare) : self::conjunction($conjuncts);
    }

    /**
     * One condition that is not a conjunction, or null when its shape is not one this class knows.
     */
    private static function single(string $bare): ?self
    {
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
        // the array that `= ANY (ARRAY[…])` does not, and the two mean the same thing. `NOT IN (…)`
        // prints as `<> ALL` with the same layer, so one pattern reads both directions.
        if (preg_match('/^\(?\s*('.$ident.')\s*(=\s*ANY|<>\s*ALL)\s*\(+\s*ARRAY\[(.+?)\]\s*\)+$/is', $bare, $m) === 1) {
            return self::fromSet($m[1], stripos($m[2], 'ALL') !== false, $m[3]);
        }

        // A comparison with one literal LAST: nothing above can reach it, and putting it first would
        // cost a reader a second of wondering whether `=` could shadow `= ANY` or `= true`.
        if (preg_match('/^\(?('.$ident.')\s*(=|<>)\s*('.self::LITERAL.')\)?$/i', $bare, $m) === 1) {
            return self::compared($m[1], $m[2], $m[3]);
        }

        return null;
    }

    /**
     * A fixed set of literals, or null when one member is not a literal.
     *
     * One member is one value: `= ANY (ARRAY['live'])` selects the rows `= 'live'` selects, and the
     * server prints `IN ('live')` as exactly that equality, so the two have to meet in one form.
     */
    private static function fromSet(string $column, bool $excluded, string $members): ?self
    {
        $values = self::sortedLiterals($members);

        if ($values === null) {
            return null;
        }

        if (count($values) === 1) {
            return self::compared($column, $excluded ? '<>' : '=', $values[0]);
        }

        $array = 'ARRAY['.implode(', ', $values).']';

        return $excluded
            ? new self($column.' <> ALL ('.$array.')', 'exclusion', $column)
            : new self($column.' = ANY ('.$array.')', 'set', $column);
    }

    /** A column compared with one literal, for either operator the server prints. */
    private static function compared(string $column, string $operator, string $literal): self
    {
        return $operator === '='
            ? new self($column.' = '.$literal, 'equality', $column)
            : new self($column.' <> '.$literal, 'inequality', $column);
    }

    /**
     * The parts of a top-level `AND`, or null when the text is not one.
     *
     * Split where the keyword stands outside every parenthesis and every literal, so neither
     * `(a AND b) OR c` nor `notes = 'x AND y'` is cut in the wrong place. A top-level `OR` beside an
     * `AND` cannot come from the server, which parenthesizes a mix, and if one ever did its part would
     * be refused below rather than read.
     *
     * @return list<string>|null
     */
    private static function conjuncts(string $bare): ?array
    {
        $text = $bare;

        while (str_starts_with($text, '(') && self::enclosesEverything($text)) {
            $text = trim(substr($text, 1, -1));
        }

        $parts = [];
        $depth = 0;
        $quoted = false;
        $start = 0;
        $length = strlen($text);

        for ($i = 0; $i < $length; $i++) {
            $char = $text[$i];

            if ($char === "'") {
                $quoted = ! $quoted;
            } elseif ($quoted) {
                continue;
            } elseif ($char === '(') {
                $depth++;
            } elseif ($char === ')') {
                $depth--;
            } elseif ($depth === 0 && $char === ' ' && preg_match('/\G\s+AND\s+/i', $text, $keyword, 0, $i) === 1) {
                $parts[] = trim(substr($text, $start, $i - $start));
                $i += strlen($keyword[0]) - 1;
                $start = $i + 1;
            }
        }

        if ($parts === []) {
            return null;
        }

        $parts[] = trim(substr($text, $start));

        return $parts;
    }

    /**
     * Whether the opening parenthesis closes on the last character, so the pair encloses everything.
     *
     * `(a AND b)` loses the pair and `(a) AND (b)` keeps both, because stripping those would join
     * `a) AND (b` into one part. Text whose parentheses never balance answers false and stays whole.
     */
    private static function enclosesEverything(string $text): bool
    {
        $depth = 0;
        $quoted = false;
        $last = strlen($text) - 1;

        foreach (str_split($text) as $i => $char) {
            if ($char === "'") {
                $quoted = ! $quoted;
            } elseif (! $quoted && $char === '(') {
                $depth++;
            } elseif (! $quoted && $char === ')' && --$depth === 0) {
                return $i === $last;
            }
        }

        return false;
    }

    /**
     * An `AND` read as the ordered set of its parts, or null when one part is not readable.
     *
     * Whole or not at all: the parts SQLens can read describe more rows than the index covers when
     * another part narrows them further, and a comparison over that larger set would be wrong about
     * which index to drop.
     *
     * @param  list<string>  $conjuncts
     */
    private static function conjunction(array $conjuncts): ?self
    {
        $readings = [];

        foreach ($conjuncts as $conjunct) {
            $reading = self::single($conjunct);

            if (! $reading instanceof self) {
                return null;
            }

            $readings[$reading->normalized] = $reading;
        }

        ksort($readings, SORT_STRING);
        $parts = array_values($readings);

        // `is_active AND is_active = true` is one condition written twice, and it groups with the
        // index that wrote it once.
        if (count($parts) === 1) {
            return $parts[0];
        }

        return new self(
            implode(' AND ', array_map(static fn (self $part): string => $part->normalized, $parts)),
            'conjunction',
            implode(', ', array_values(array_unique(array_map(static fn (self $part): string => $part->column, $parts)))),
            $parts,
        );
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
            'exclusion' => sprintf('the rows whose %s is none of a fixed set', $this->column),
            'equality' => sprintf('the rows whose %s is one value', $this->column),
            'conjunction' => 'the rows '.$this->joined(array_map(
                static fn (self $part): string => substr($part->describe(), strlen('the rows ')),
                $this->parts,
            )),
            default => sprintf('the rows whose %s differs from one value', $this->column),
        };
    }

    /**
     * Two or more clauses as one English list: `a and b`, `a, b and c`.
     *
     * @param  list<string>  $clauses
     */
    private function joined(array $clauses): string
    {
        return implode(', ', array_slice($clauses, 0, -1)).' and '.implode('', array_slice($clauses, -1));
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
            if (preg_match('/^'.self::LITERAL.'$/', $part) !== 1) {
                return null;
            }

            $literals[] = $part;
        }

        sort($literals, SORT_STRING);

        return $literals;
    }
}
