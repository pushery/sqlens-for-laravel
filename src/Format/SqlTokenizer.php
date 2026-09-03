<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

/**
 * SQL split into the pieces a formatter may move, with the pieces it must never touch marked.
 *
 * ## Why a tokenizer and not a regex
 *
 * A formatter's one unforgivable bug is changing what a statement MEANS, and every way to do that
 * runs through the same mistake: treating the inside of a string literal, a quoted identifier or a
 * comment as SQL. `where note = 'select 1'` contains a keyword that must not be upper-cased;
 * `"select"` is a column somebody named badly and not a keyword at all; a comment can contain
 * anything.
 *
 * A regex over the whole statement cannot know which of those it is inside. A scanner that tracks
 * the state it is in can, and that is the entire reason this class exists.
 *
 * ## It preserves, it does not interpret
 *
 * Every token carries its source text verbatim. Reassembling the tokens in order reproduces the
 * input byte for byte, and an arm holds that: a formatter is only trustworthy if the thing it starts
 * from is lossless.
 */
final readonly class SqlTokenizer
{
    /**
     * @return list<SqlToken>
     */
    public static function tokenize(string $sql): array
    {
        $tokens = [];
        $length = strlen($sql);
        $at = 0;

        while ($at < $length) {
            $char = $sql[$at];

            // Whitespace collapses into one token; the formatter decides what it becomes. Kept as a
            // token rather than dropped so reassembly is lossless.
            if (ctype_space($char)) {
                $run = self::runOf($sql, $at, static fn (string $c): bool => ctype_space($c));
                $tokens[] = new SqlToken(SqlTokenKind::Whitespace, $run);
                $at += strlen($run);

                continue;
            }

            // Line comment. It runs to the end of the line and NOTHING inside it is SQL.
            if ($char === '-' && ($sql[$at + 1] ?? '') === '-') {
                $end = strpos($sql, "\n", $at);
                $run = $end === false ? substr($sql, $at) : substr($sql, $at, $end - $at);
                $tokens[] = new SqlToken(SqlTokenKind::Comment, $run);
                $at += strlen($run);

                continue;
            }

            // Block comment. Unterminated is possible in real input, and the scanner takes the rest
            // of the string rather than looping forever.
            if ($char === '/' && ($sql[$at + 1] ?? '') === '*') {
                $end = strpos($sql, '*/', $at + 2);
                $run = $end === false ? substr($sql, $at) : substr($sql, $at, $end - $at + 2);
                $tokens[] = new SqlToken(SqlTokenKind::Comment, $run);
                $at += strlen($run);

                continue;
            }

            // ⚠️ DOLLAR-QUOTING, and it has to be tried BEFORE the word scan — `$` is a word
            // character here (PostgreSQL allows it in identifiers), so a `$$` left to that scan
            // becomes a word and the FUNCTION BODY AFTER IT IS TREATED AS SQL. A formatter would
            // then reflow the body of a `CREATE FUNCTION`, which is the same class of damage as
            // formatting a PHP file: the output looks formatted and the code inside is destroyed.
            //
            // Both forms, because both are ordinary: `$$ … $$` in most migrations, and `$tag$ … $tag$`
            // wherever a body itself contains `$$`.
            if ($char === '$' && ($run = self::dollarQuotedRun($sql, $at)) !== null) {
                $tokens[] = new SqlToken(SqlTokenKind::String, $run);
                $at += strlen($run);

                continue;
            }

            // A quoted run: a string literal, or an identifier in any of the three quoting styles
            // both engines between them accept. The DELIMITER is what separates the two kinds, and
            // the doubled-delimiter escape is what stops the scan ending early on `'it''s'`.
            if (in_array($char, ["'", '"', '`'], true)) {
                $run = self::quotedRun($sql, $at, $char);
                $tokens[] = new SqlToken(
                    $char === "'" ? SqlTokenKind::String : SqlTokenKind::QuotedIdentifier,
                    $run,
                );
                $at += strlen($run);

                continue;
            }

            if (in_array($char, [',', '(', ')', ';'], true)) {
                $tokens[] = new SqlToken(SqlTokenKind::Punctuation, $char);
                $at++;

                continue;
            }

            // A bare word: keyword, identifier or number. Which of those it is, is the WORD's
            // business rather than the scanner's — `SqlToken::isKeyword()` answers it against a
            // list, and a scanner that decided here would need that list too.
            if (ctype_alnum($char) || $char === '_' || $char === '$' || $char === '.') {
                $run = self::runOf($sql, $at, static fn (string $c): bool => ctype_alnum($c) || $c === '_' || $c === '$' || $c === '.');
                $tokens[] = new SqlToken(SqlTokenKind::Word, $run);
                $at += strlen($run);

                continue;
            }

            // Everything else — operators, parameters, whatever an engine accepts that this scanner
            // has no opinion about. Preserved verbatim, one character at a time, because a formatter
            // that guessed at an operator it did not recognize would be guessing about meaning.
            $tokens[] = new SqlToken(SqlTokenKind::Operator, $char);
            $at++;
        }

        return $tokens;
    }

    /**
     * A dollar-quoted run including both tags, or null when this `$` does not open one.
     *
     * PostgreSQL's answer to escaping: `$$ body $$`, or `$tag$ body $tag$` when the body itself
     * contains `$$`. Everything between the tags is data — most often a whole function body in
     * another language entirely — and a formatter that treated it as SQL would reflow PL/pgSQL,
     * Python or JavaScript as though it were a `SELECT`.
     *
     * Null rather than a guess when the `$` is not a tag opener: `$1` is a parameter placeholder and
     * `a$b` is a legal identifier, and swallowing either as a quote would eat the rest of the
     * statement.
     */
    private static function dollarQuotedRun(string $sql, int $at): ?string
    {
        // The tag is `$`, an optional identifier, `$`. An identifier here is letters, digits and
        // underscores — and it may not START with a digit, which is exactly what separates a tag
        // from the `$1` placeholder form.
        if (preg_match('/\A\$([A-Za-z_][A-Za-z0-9_]*)?\$/', substr($sql, $at), $opener) !== 1) {
            return null;
        }

        $tag = $opener[0];
        $end = strpos($sql, $tag, $at + strlen($tag));

        // Unterminated: take the rest, for the reason the string scanner states. Inventing a closing
        // tag would hand the formatter SQL the author never wrote.
        return $end === false ? substr($sql, $at) : substr($sql, $at, $end - $at + strlen($tag));
    }

    /**
     * A quoted run INCLUDING both delimiters, with the doubled-delimiter escape honored.
     *
     * `'it''s'` is one literal and not two, and a scan that stopped at the second quote would split
     * it — after which every subsequent token is inside-out and the formatter would happily
     * upper-case the contents of a string.
     */
    private static function quotedRun(string $sql, int $at, string $delimiter): string
    {
        $length = strlen($sql);
        $cursor = $at + 1;

        while ($cursor < $length) {
            if ($sql[$cursor] !== $delimiter) {
                $cursor++;

                continue;
            }

            if (($sql[$cursor + 1] ?? '') === $delimiter) {
                $cursor += 2;

                continue;
            }

            return substr($sql, $at, $cursor - $at + 1);
        }

        // Unterminated. Real input contains it — a truncated log line, a statement cut by a length
        // limit — and taking the rest is the only answer that neither loops nor invents a closing
        // quote the author did not write.
        return substr($sql, $at);
    }

    /** @param callable(string): bool $matches */
    private static function runOf(string $sql, int $at, callable $matches): string
    {
        $length = strlen($sql);
        $cursor = $at;

        while ($cursor < $length && $matches($sql[$cursor])) {
            $cursor++;
        }

        return substr($sql, $at, $cursor - $at);
    }
}
