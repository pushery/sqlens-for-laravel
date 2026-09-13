<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Understanding;

/**
 * A delimited list split only where the delimiter stands at the TOP level — outside every
 * parenthesis and every quoted run.
 *
 * ## Why a plain explode was wrong, and exactly where
 *
 * The catalog carries an index's key positions as one comma-joined string, and a table carries its
 * members as `name(col, col); other(col)`. Both encodings assumed that the separator never occurs
 * inside a key position. For a column that holds. For an expression it does not, and PostgreSQL
 * hands the expression over verbatim: a real search index keys on
 *
 *     (((title)::text || ' '::text) || (COALESCE(heading, ''::character varying))::text)
 *
 * which is ONE key position with a comma inside `COALESCE(…)`. Exploded, it became two pieces that
 * are not key positions at all, and the index was reported as not understood although nothing about
 * it was unclear. An expression may carry a semicolon inside a string literal just as legally, and
 * that one took the member list itself apart.
 *
 * ## Why balance is enough
 *
 * Every piece a reader produces is balanced: a deparsed expression closes each parenthesis it opens,
 * a string literal closes its quote (a doubled quote inside one toggles twice and changes nothing),
 * and a quoted identifier — PostgreSQL allows a column named `a,b`, rendered `"a,b"` — closes its
 * double quote. So a separator at depth zero, outside both kinds of quote, is a real boundary, and
 * every other occurrence belongs to the piece around it.
 *
 * ## What happens to text that does not balance
 *
 * It is split the old way, on every separator. An unbalanced string is not a list this reading can
 * trust, and the tempting alternative — carry on at depth one to the end — would swallow every
 * later member into one piece, so a single malformed entry would silently delete the rest of a
 * table's indexes from every rule that reads the list. Split flat, the malformed piece stays
 * malformed and visible: {@see IndexComprehension} still refuses a key position that does not
 * balance, which is the refusal a broken reading deserves.
 *
 * Balance is judged along the way, not only at the end. A closing parenthesis with nothing open
 * cannot be balanced by anything after it, even when a later opening one brings the count back to
 * zero: every separator in between sits below the top level, and a check of the final count alone
 * folded them all into one piece.
 */
final class TopLevelList
{
    /**
     * The pieces of a delimited list, each trimmed, in order — empty pieces included.
     *
     * @param  non-empty-string  $delimiter  a single ASCII character, never a parenthesis or a quote
     * @return list<string>
     */
    public static function split(string $text, string $delimiter): array
    {
        $pieces = [];
        $current = '';
        $depth = 0;
        $quote = null;
        $length = strlen($text);

        for ($i = 0; $i < $length; $i++) {
            $character = $text[$i];

            if ($quote !== null) {
                $current .= $character;

                if ($character === $quote) {
                    $quote = null;
                }

                continue;
            }

            if ($character === "'" || $character === '"') {
                $quote = $character;
            } elseif ($character === '(') {
                $depth++;
            } elseif ($character === ')') {
                $depth--;

                // Nothing was open, so nothing later can balance this text. A count checked only at
                // the end calls it balanced once an opening parenthesis evens it out, and every
                // separator in between sat below the top level and was folded into one piece.
                if ($depth < 0) {
                    return self::flat($text, $delimiter);
                }
            } elseif ($character === $delimiter && $depth === 0) {
                $pieces[] = trim($current);
                $current = '';

                continue;
            }

            $current .= $character;
        }

        if ($depth !== 0 || $quote !== null) {
            return self::flat($text, $delimiter);
        }

        $pieces[] = trim($current);

        return $pieces;
    }

    /**
     * The old reading, at every separator, for text this splitter cannot trust.
     *
     * @param  non-empty-string  $delimiter
     * @return list<string>
     */
    private static function flat(string $text, string $delimiter): array
    {
        return array_map(trim(...), explode($delimiter, $text));
    }
}
