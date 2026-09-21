<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

use Pushery\SQLens\Contracts\DriverCanonicalization;

/**
 * Blanks the string literals in a canonical statement, so a rule scans syntax and not data.
 *
 * Canonicalization leaves literal CONTENT untouched by design: inside quotes a keyword is data, and
 * rewriting it would make the tool edit the SQL it is describing. That decision is right, and it is
 * what puts the burden here — every rule that greps for a clause has to blank the literals first, or
 * a column default spelling `LOCK=` decides a rule about clauses.
 *
 * ## Why this is one class rather than a regex per rule
 *
 * It used to be a regex per rule, and there were seven copies of the same one:
 *
 * ```php
 * preg_replace("/'(?:[^']|'')*'/", "''", $canonical)
 * ```
 *
 * Seven copies is not a tidiness problem. That pattern hard-codes an answer to two questions the
 * DRIVER owns, and it gets both wrong for MySQL:
 *
 * - **Which delimiters open a literal.** MySQL's manual, under String Literals, says a string is
 *   enclosed within either single quote or double quote characters. `"` is only an identifier quote
 *   under `ANSI_QUOTES`, which is not in the default `sql_mode` and which Laravel's MySQL connection
 *   does not set. So `VALUES ("set lock_wait_timeout = 5")` is a literal, and the pattern above sees
 *   `SET lock_wait_timeout =` as syntax — the false-silence direction, on a rule whose whole job is
 *   to notice that the timeout is missing.
 * - **Whether a backslash escapes the delimiter.** MySQL escapes with a backslash by default;
 *   PostgreSQL does not, because `standard_conforming_strings` is on. The pattern above encodes the
 *   PostgreSQL answer, so on MySQL `'it\'s LOCK=ALGORITHM'` masks to `''s LOCK=ALGORITHM'` and the
 *   literal's content escapes into the scan. ⚠️ **That one needs no double quote and no raw SQL** —
 *   any MySQL migration with a backslash-escaped apostrophe in a default already has it.
 *
 * Both are properties of the engine, and both already had an answer on {@see DriverCanonicalization}
 * — `stringLiteralDelimiters()` and `usesBackslashStringEscapes()`, which the splitter has been
 * reading all along. The rules were the only layer that asked nobody.
 *
 * ## Why a scanner and not a cleverer pattern
 *
 * With two delimiters, a doubling rule and an optional backslash escape, the pattern that states the
 * grammar correctly is longer than the scanner and cannot be read by the next person. The scanner
 * also has to skip quoted IDENTIFIERS, which no version of the regex did: MySQL permits an
 * apostrophe inside backticks, so ``ALTER TABLE `it's` …`` would otherwise open a literal that never
 * closes, and a fix for one mis-parse would have introduced another.
 *
 * A masked literal keeps its delimiters — `'…'` becomes `''` — so the statement still says a literal
 * was here. Rules depend on that: an empty literal is a value, and deleting it outright would turn
 * `VALUES ('x')` into `VALUES ()`, which no longer parses as the thing it was.
 */
final class StringLiteralMask
{
    /** @var array<string, self> */
    private static array $memo = [];

    /**
     * @param  list<string>  $delimiters
     */
    private function __construct(
        private readonly array $delimiters,
        private readonly bool $backslashEscapes,
        private readonly string $identifierQuote,
    ) {}

    /**
     * The mask a driver's own grammar implies.
     *
     * Memoized per driver class rather than per instance: the three inputs are constants of the
     * engine, so two instances cannot disagree, and a rule that masks once per statement would
     * otherwise rebuild this on every call.
     */
    public static function forDriver(DriverCanonicalization $driver): self
    {
        return self::$memo[$driver::class] ??= new self(
            $driver->stringLiteralDelimiters(),
            $driver->usesBackslashStringEscapes(),
            $driver->quotingCharacter(),
        );
    }

    /**
     * The statement with every string literal emptied, and everything else byte-for-byte unchanged.
     */
    public function apply(string $sql): string
    {
        $out = '';
        $length = strlen($sql);
        $i = 0;

        while ($i < $length) {
            $char = $sql[$i];

            // A quoted identifier is copied whole. Its content is not data to be masked, and it may
            // legally contain a delimiter — see the class docblock.
            if ($this->identifierQuote !== '' && $char === $this->identifierQuote) {
                $end = $this->endOfQuotedIdentifier($sql, $i);
                $out .= substr($sql, $i, $end - $i);
                $i = $end;

                continue;
            }

            if (! in_array($char, $this->delimiters, true)) {
                $out .= $char;
                $i++;

                continue;
            }

            $end = $this->endOfLiteral($sql, $i, $char);
            $out .= $char.$char;
            $i = $end;
        }

        return $out;
    }

    /**
     * One past the closing delimiter, or the end of the string when the literal never closes.
     *
     * An unterminated literal is masked to the end rather than left alone. The alternative — copying
     * the tail verbatim — would put unmasked literal content back into the scan, which is the exact
     * failure this class exists to prevent. The splitter refuses such a batch upstream with
     * `unterminatedLiteral`, so a rule normally never sees one; this decides what happens when a
     * caller masks a fragment rather than a whole statement.
     */
    private function endOfLiteral(string $sql, int $start, string $delimiter): int
    {
        $length = strlen($sql);
        $i = $start + 1;

        while ($i < $length) {
            $char = $sql[$i];

            if ($this->backslashEscapes && $char === '\\') {
                $i += 2;

                continue;
            }

            if ($char !== $delimiter) {
                $i++;

                continue;
            }

            // A doubled delimiter is one escaped character, not a close followed by an open. This
            // holds on both engines and independently of the backslash rule.
            if (($sql[$i + 1] ?? '') === $delimiter) {
                $i += 2;

                continue;
            }

            return $i + 1;
        }

        return $length;
    }

    /**
     * One past the closing identifier quote, or the end of the string when it never closes.
     *
     * A doubled quote is an escaped quote here too — MySQL writes a backtick inside backticks by
     * doubling it, and PostgreSQL does the same with double quotes. A backslash is NOT an escape
     * inside a quoted identifier on either engine, so `usesBackslashStringEscapes()` deliberately
     * does not reach this loop.
     */
    private function endOfQuotedIdentifier(string $sql, int $start): int
    {
        $length = strlen($sql);
        $i = $start + 1;

        while ($i < $length) {
            if ($sql[$i] !== $this->identifierQuote) {
                $i++;

                continue;
            }

            if (($sql[$i + 1] ?? '') === $this->identifierQuote) {
                $i += 2;

                continue;
            }

            return $i + 1;
        }

        return $length;
    }
}
