<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

use Pushery\SQLens\Contracts\DriverCanonicalization;

/**
 * Blanks the string literals in a canonical statement, so a rule scans syntax and not data.
 *
 * Canonicalization leaves literal content untouched by design: inside quotes a keyword is data, and
 * rewriting it would make the tool edit the SQL it is describing. That decision is right, and it is
 * what puts the burden here — every rule that greps for a clause has to blank the literals first, or
 * a column default spelling `LOCK=` decides a rule about clauses.
 *
 * ## Why this is one class rather than a regex per rule
 *
 * A regex per rule would mean seven copies of the same one:
 *
 * ```php
 * preg_replace("/'(?:[^']|'')*'/", "''", $canonical)
 * ```
 *
 * Seven copies would not be a tidiness problem. That pattern hard-codes an answer to two questions
 * the driver owns, and it gets both wrong for MySQL:
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
 *   literal's content escapes into the scan. **That one needs no double quote and no raw SQL** —
 *   any MySQL migration with a backslash-escaped apostrophe in a default already has it.
 *
 * Both are properties of the engine, and both already had an answer on {@see DriverCanonicalization}
 * — `stringLiteralDelimiters()` and `usesBackslashStringEscapes()`, which the splitter reads too.
 * This class asks the driver, so the rules do as well.
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
 *
 * ## A second reader: a log that must not carry the values
 *
 * The runtime guards write the statement a query executed into the application's log, where row data
 * reaches readers the database never granted it to. {@see shaped()} is the same walk for that reader:
 * every literal keeps its delimiters and becomes its length, `'alice@example.com'` becoming
 * `'<string(17)>'`, so the log still shows where a value stood and never what it was. The statement
 * is raw rather than canonical there, so this walk also reads comments and dollar quotes, which a
 * canonical statement no longer needs.
 *
 * {@see coarse()} is what remains for an engine that registered no grammar: without one a quoted value
 * cannot be told from a quoted name, and the only mask that cannot be wrong about where a literal ends
 * is one that masks from the first quote to the last.
 */
final class StringLiteralMask
{
    /** What {@see coarse()} writes in place of everything it masks. */
    public const string COARSE = '<masked>';

    /** @var array<string, self> */
    private static array $memo = [];

    /**
     * @param  list<string>  $delimiters
     * @param  list<string>  $lineComments
     */
    private function __construct(
        private readonly array $delimiters,
        private readonly bool $backslashEscapes,
        private readonly string $identifierQuote,
        private readonly array $lineComments,
        private readonly bool $blockComments,
        private readonly bool $dollarQuotes,
    ) {}

    /**
     * The mask a driver's own grammar implies.
     *
     * Memoized per driver class rather than per instance: the inputs are constants of the engine,
     * so two instances cannot disagree, and a rule that masks once per statement would otherwise
     * rebuild this on every call.
     */
    public static function forDriver(DriverCanonicalization $driver): self
    {
        return self::$memo[$driver::class] ??= new self(
            $driver->stringLiteralDelimiters(),
            $driver->usesBackslashStringEscapes(),
            $driver->quotingCharacter(),
            array_values(array_filter($driver->commentSyntaxes(), static fn (string $marker): bool => $marker !== '/*')),
            in_array('/*', $driver->commentSyntaxes(), true),
            $driver->supportsDollarQuotedStrings(),
        );
    }

    /**
     * Everything from the first quote to the last replaced by {@see COARSE}, for an engine whose
     * grammar is not known.
     *
     * Without a grammar neither question a literal raises can be answered: which quote character
     * opens one, and whether a backslash escapes it. Every other reading can end a literal early and
     * log the rest of it as text. Any value the statement quotes lies between its first quote and its
     * last, so masking that span is correct whatever the engine does, at the cost of the names and
     * operators in between.
     */
    public static function coarse(string $sql): string
    {
        $first = strcspn($sql, "'\"");

        if ($first === strlen($sql)) {
            return $sql;
        }

        $last = max((int) strrpos($sql, "'"), (int) strrpos($sql, '"'));

        return substr($sql, 0, $first).self::COARSE.($last > $first ? substr($sql, $last + 1) : '');
    }

    /**
     * The statement with every literal's content replaced by its length, and everything else as
     * written: `'alice@example.com'` becomes `'<string(17)>'`.
     *
     * What counts as a literal is the driver's answer, as in {@see apply()}, and the walk adds three
     * things a raw statement can hold:
     *
     * - **Comments.** Their text is shaped on its own, so the apostrophe in a comment that says `it's`
     *   masks the rest of that comment and nothing after it. Read as the start of a literal it would
     *   end that literal at the next quote, and the value after it would be logged as text.
     * - **Dollar quotes**, on an engine that has them: `$$…$$` and `$tag$…$tag$` keep their tags.
     * - **`E'…'`**, the escape-string form, is read with backslash escapes even where plain literals
     *   have none. Read without them, `E'it\'s'` would end at the escaped quote.
     *
     * A literal that never closes is shaped to the end of the statement rather than left as text.
     */
    public function shaped(string $sql): string
    {
        $out = '';
        $length = strlen($sql);
        $i = 0;

        while ($i < $length) {
            $char = $sql[$i];
            $lineComment = ScanAt::firstOf($sql, $i, $this->lineComments);

            if ($lineComment !== null) {
                $newline = strpos($sql, "\n", $i);
                $end = $newline === false ? $length : $newline;
                $from = $i + strlen($lineComment);
                $out .= $lineComment.$this->shaped(substr($sql, $from, $end - $from));
                $i = $end;

                continue;
            }

            if ($this->blockComments && ScanAt::startsWith($sql, $i, '/*')) {
                $close = strpos($sql, '*/', $i + 2);
                $out .= '/*'.$this->shaped(substr($sql, $i + 2, ($close === false ? $length : $close) - $i - 2)).($close === false ? '' : '*/');
                $i = $close === false ? $length : $close + 2;

                continue;
            }

            if ($this->dollarQuotes && $char === '$' && preg_match('/\G\$\w*\$/', $sql, $tag, 0, $i) === 1) {
                $open = $tag[0];
                $from = $i + strlen($open);
                $close = strpos($sql, $open, $from);
                $out .= $open.$this->shape(substr($sql, $from, ($close === false ? $length : $close) - $from)).($close === false ? '' : $open);
                $i = $close === false ? $length : $close + strlen($open);

                continue;
            }

            $identifierEnd = $char === $this->identifierQuote ? QuotedSpan::endOfQuotedIdentifier($sql, $i, $char) : null;

            // A quoted identifier is copied whole, as in `apply()`. One that never closes is not
            // skipped to the end: its quote is copied, and the walk goes on reading literals.
            if ($identifierEnd !== null) {
                $out .= substr($sql, $i, $identifierEnd - $i);
                $i = $identifierEnd;

                continue;
            }

            if (! in_array($char, $this->delimiters, true)) {
                $out .= $char;
                $i++;

                continue;
            }

            $end = QuotedSpan::endOfLiteral($sql, $i, $char, $this->backslashEscapes || $this->opensAnEscapeString($sql, $i));
            $out .= $char.$this->shape(substr($sql, $i + 1, ($end ?? $length + 1) - $i - 2)).($end === null ? '' : $char);
            $i = $end ?? $length;
        }

        return $out;
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

    /** A literal's content as the log may show it: its length in characters, nothing it said. */
    private function shape(string $content): string
    {
        return sprintf('<string(%d)>', mb_strlen($content));
    }

    /**
     * Whether the quote at $at opens an escape string: a single quote right after a standalone `E`.
     *
     * Standalone means the character before the `E` does not continue a word, so the `E` that ends
     * `ELSE'x'` does not count. On an engine whose plain literals take backslash escapes already,
     * the answer changes nothing.
     */
    private function opensAnEscapeString(string $sql, int $at): bool
    {
        if ($sql[$at] !== "'" || $at === 0 || strtoupper($sql[$at - 1]) !== 'E') {
            return false;
        }

        return $at === 1 || preg_match('/[A-Za-z0-9_$]/', $sql[$at - 2]) !== 1;
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
        return QuotedSpan::endOfLiteral($sql, $start, $delimiter, $this->backslashEscapes) ?? strlen($sql);
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
        return QuotedSpan::endOfQuotedIdentifier($sql, $start, $this->identifierQuote) ?? strlen($sql);
    }
}
