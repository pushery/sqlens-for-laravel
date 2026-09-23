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
 * ## A token is what the server reads as one
 *
 * The formatter puts a space between two tokens, so a scanner that emitted every operator character
 * as a token of its own would write `total >= 0` back as `total > = 0`, `h::text` as `h : : TEXT`,
 * `E'a\nb'` as `E 'a\nb'` and `1.5e-3` as `1.5e - 3`: syntax errors, written back into the file.
 * Protecting the inside of a string is not enough; the boundaries between tokens matter as much.
 *
 * So the rule is the server's lexer, per dialect, and nothing looser. Two tokens are two tokens only
 * where PostgreSQL or MySQL would read two, which is what makes a space between them safe:
 *
 * - **Operators.** PostgreSQL reads the longest run of `+ - * / < > = ~ ! @ # % ^ & | ` ?` as one
 *   operator, except that a run may not end in `+` or `-` unless it also holds one of
 *   `~ ! @ # % ^ & | ` ?` (so `a=-1` is `=` and `-1`), and may not contain `--` or `/*`. `::` and
 *   `:=` are tokens of their own. MySQL has a fixed set (`<=>`, `->>`, `:=`, `&&`, …) and reads the
 *   rest one character at a time.
 * - **Literals.** A prefix belongs to its string: `E'…'`, `B'…'`, `X'…'`, `N'…'`, `U&'…'` on
 *   PostgreSQL, `N'…'`, `X'…'`, `B'…'`, `_utf8mb4'…'` on MySQL. A number keeps its exponent.
 * - **Escapes.** PostgreSQL's plain strings take `''` only; `E'…'` takes backslashes as well. MySQL's
 *   strings take both, because backslash escapes are its default.
 * - **Comments.** `--` to the end of the line, and on MySQL only when whitespace follows it; `#`
 *   on MySQL; `/* … * /` everywhere, nesting on PostgreSQL.
 * - **MySQL variables.** `@name` and `@@scope.name` are one token.
 *
 * ## It preserves, it does not interpret
 *
 * Every token carries its source text verbatim. Reassembling the tokens in order reproduces the
 * input byte for byte, and an arm holds that: a formatter is only trustworthy if the thing it starts
 * from is lossless.
 */
final readonly class SqlTokenizer
{
    /** The characters PostgreSQL builds an operator from. */
    private const string POSTGRES_OPERATOR_CHARACTERS = '+-*/<>=~!@#%^&|`?';

    /** The ones that allow a multi-character PostgreSQL operator to end in `+` or `-`. */
    private const string POSTGRES_OPERATOR_TRAILING_SIGN_ALLOWED = '~!@#%^&|`?';

    /** MySQL's multi-character operators, longest first so a prefix never wins. */
    private const array MYSQL_OPERATORS = ['<=>', '->>', '<<', '>>', '<=', '>=', '<>', '!=', '->', '&&', '||'];

    /**
     * @return list<SqlToken>
     */
    public static function tokenize(string $sql, Dialect $dialect): array
    {
        $tokens = [];
        $length = strlen($sql);
        $at = 0;
        $postgres = $dialect === Dialect::Pgsql;

        while ($at < $length) {
            $char = $sql[$at];
            $next = $sql[$at + 1] ?? '';

            // Whitespace collapses into one token; the formatter decides what it becomes. Kept as a
            // token rather than dropped so reassembly is lossless.
            if (ctype_space($char)) {
                $run = self::runOf($sql, $at, static fn (string $c): bool => ctype_space($c));
                $tokens[] = new SqlToken(SqlTokenKind::Whitespace, $run);
                $at += strlen($run);

                continue;
            }

            // Line comment. It runs to the end of the line and NOTHING inside it is SQL. MySQL reads
            // `--` as a comment only when whitespace follows it: `5--1` is five minus minus one there.
            if (($char === '-' && $next === '-' && ($postgres || $at + 2 >= $length || ctype_space($sql[$at + 2])))
                || (! $postgres && $char === '#')) {
                $end = strpos($sql, "\n", $at);
                $run = $end === false ? substr($sql, $at) : substr($sql, $at, $end - $at);
                $tokens[] = new SqlToken(SqlTokenKind::Comment, $run);
                $at += strlen($run);

                continue;
            }

            // Block comment. PostgreSQL nests them and MySQL does not, so `/* a /* b */ c */` is one
            // comment on the first and a comment followed by `c */` on the second. Unterminated is
            // possible in real input, and the scanner takes the rest rather than looping forever.
            if ($char === '/' && $next === '*') {
                $run = self::blockComment($sql, $at, $postgres);
                $tokens[] = new SqlToken(SqlTokenKind::Comment, $run);
                $at += strlen($run);

                continue;
            }

            // Dollar-quoting, and it has to be tried before the word scan — `$` is a word
            // character here (PostgreSQL allows it in identifiers), so a `$$` left to that scan
            // becomes a word and the function body after it is treated as SQL. A formatter would
            // then reflow the body of a `CREATE FUNCTION`, which is the same class of damage as
            // formatting a PHP file: the output looks formatted and the code inside is destroyed.
            //
            // Both forms, because both are ordinary: `$$ … $$` in most migrations, and `$tag$ … $tag$`
            // wherever a body itself contains `$$`. PostgreSQL only: MySQL has no dollar quoting.
            if ($postgres && $char === '$' && ($run = self::dollarQuotedRun($sql, $at)) !== null) {
                $tokens[] = new SqlToken(SqlTokenKind::String, $run);
                $at += strlen($run);

                continue;
            }

            // A literal with a prefix is ONE token. `E 'x'` is not `E'x'` on PostgreSQL, and a space
            // written between the two turns an escape string into a syntax error.
            if (($prefixed = self::prefixedLiteral($sql, $at, $postgres)) instanceof SqlToken) {
                $tokens[] = $prefixed;
                $at += strlen($prefixed->text);

                continue;
            }

            // A quoted run: a string literal, or an identifier in any of the three quoting styles
            // both engines between them accept. The DELIMITER is what separates the two kinds, and
            // the doubled-delimiter escape is what stops the scan ending early on `'it''s'`. MySQL
            // also ends nothing at `\'`, because backslash escapes are its default.
            if (in_array($char, ["'", '"', '`'], true)) {
                $run = self::quotedRun($sql, $at, $char, ! $postgres && $char !== '`');
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

            // A number, with its exponent. `1.5e-3` read as a word stops at the `e`, and the sign
            // after it becomes an operator the formatter spaces out.
            if (ctype_digit($char) || ($char === '.' && ctype_digit($next))) {
                $run = self::number($sql, $at);
                $tokens[] = new SqlToken(SqlTokenKind::Word, $run);
                $at += strlen($run);

                continue;
            }

            // A MySQL variable: `@name`, `@'quoted'`, `@@session.sql_mode`. On PostgreSQL `@` is an
            // operator character (absolute value), and the operator scan below takes it.
            if (! $postgres && $char === '@' && ($variable = self::mysqlVariable($sql, $at)) !== null) {
                $tokens[] = new SqlToken(SqlTokenKind::Word, $variable);
                $at += strlen($variable);

                continue;
            }

            // A bare word: keyword, identifier or number. Which of those it is, is the WORD's
            // business rather than the scanner's — `SqlToken::isKeyword()` answers it against a
            // list, and a scanner that decided here would need that list too.
            if (self::isWordCharacter($char)) {
                $run = self::runOf($sql, $at, self::isWordCharacter(...));
                $tokens[] = new SqlToken(SqlTokenKind::Word, $run);
                $at += strlen($run);

                continue;
            }

            $operator = self::operator($sql, $at, $postgres);
            $tokens[] = new SqlToken(SqlTokenKind::Operator, $operator);
            $at += strlen($operator);
        }

        return $tokens;
    }

    private static function isWordCharacter(string $char): bool
    {
        return ctype_alnum($char) || $char === '_' || $char === '$' || $char === '.' || ord($char) >= 0x80;
    }

    /**
     * An operator as the server reads it, or a single character this scanner has no opinion about.
     *
     * The fallback is one character on purpose: `[`, `]`, `{` or a backslash is preserved verbatim,
     * and a scanner that guessed at a longer token it does not recognize would be guessing about
     * meaning.
     */
    private static function operator(string $sql, int $at, bool $postgres): string
    {
        $pair = substr($sql, $at, 2);

        // Both dialects: `:=` assigns (PL/pgSQL, named arguments, MySQL variables), and `::` is
        // PostgreSQL's cast. Neither is built from the operator characters, so the scans below would
        // split them.
        if ($pair === ':=' || ($postgres && $pair === '::')) {
            return $pair;
        }

        if (! $postgres) {
            foreach (self::MYSQL_OPERATORS as $operator) {
                if (substr($sql, $at, strlen($operator)) === $operator) {
                    return $operator;
                }
            }

            return $sql[$at];
        }

        if (! str_contains(self::POSTGRES_OPERATOR_CHARACTERS, $sql[$at])) {
            return $sql[$at];
        }

        $run = '';
        $length = strlen($sql);

        for ($cursor = $at; $cursor < $length && str_contains(self::POSTGRES_OPERATOR_CHARACTERS, $sql[$cursor]); $cursor++) {
            // A comment opener ends the operator in front of it: `a+--note` is `+` and a comment.
            if ($run !== '' && in_array(substr($sql, $cursor, 2), ['--', '/*'], true)) {
                break;
            }

            $run .= $sql[$cursor];
        }

        // The trailing-sign rule, from PostgreSQL's lexer: without one of the special characters,
        // a multi-character operator gives its trailing `+` or `-` back, so `=-1` compares with a
        // negative number instead of calling an operator named `=-`.
        if (strpbrk($run, self::POSTGRES_OPERATOR_TRAILING_SIGN_ALLOWED) === false) {
            while (strlen($run) > 1 && in_array($run[strlen($run) - 1], ['+', '-'], true)) {
                $run = substr($run, 0, -1);
            }
        }

        return $run;
    }

    /** A number: decimal with an optional fraction and exponent, or a hex, octal or binary integer. */
    private static function number(string $sql, int $at): string
    {
        preg_match('/\G(?:0[xX][0-9A-Fa-f_]+|0[oO][0-7_]+|0[bB][01_]+|(?:\d[\d_]*(?:\.[\d_]*)?|\.\d[\d_]*)(?:[eE][+-]?\d[\d_]*)?)/', $sql, $match, 0, $at);

        $number = $match[0] ?? $sql[$at];

        // Whatever word characters follow stay attached, the way the word scan kept them before:
        // `1abc` is one token either way, and splitting it would write a space the author did not.
        $tail = self::runOf($sql, $at + strlen($number), self::isWordCharacter(...));

        return $number.$tail;
    }

    /**
     * A string or identifier with its prefix, or null when nothing here opens one.
     *
     * Asked only where a token starts, so the prefix is a whole word of one letter (or `U&`, or a
     * character set name): `date'2026-09-13'` stays a type name and a string, which is how both
     * servers read it.
     */
    private static function prefixedLiteral(string $sql, int $at, bool $postgres): ?SqlToken
    {
        $rest = substr($sql, $at, 3);
        $letter = strtoupper($sql[$at]);

        if ($postgres) {
            // `U&'…'` and `U&"…"`: a Unicode escape string or identifier.
            if (strtoupper(substr($rest, 0, 2)) === 'U&' && in_array($rest[2] ?? '', ["'", '"'], true)) {
                $quote = $rest[2];
                $run = substr($sql, $at, 2).self::quotedRun($sql, $at + 2, $quote, false);

                return new SqlToken($quote === "'" ? SqlTokenKind::String : SqlTokenKind::QuotedIdentifier, $run);
            }

            if (in_array($letter, ['E', 'B', 'X', 'N'], true) && ($rest[1] ?? '') === "'") {
                return new SqlToken(SqlTokenKind::String, $sql[$at].self::quotedRun($sql, $at + 1, "'", $letter === 'E'));
            }

            return null;
        }

        if (in_array($letter, ['N', 'X', 'B'], true) && ($rest[1] ?? '') === "'") {
            return new SqlToken(SqlTokenKind::String, $sql[$at].self::quotedRun($sql, $at + 1, "'", $letter === 'N'));
        }

        // A character set introducer: `_utf8mb4'…'`, `_binary'…'`.
        if ($sql[$at] === '_' && preg_match('/\G_[A-Za-z0-9]+(?=[\'"])/', $sql, $introducer, 0, $at) === 1) {
            $quote = $sql[$at + strlen($introducer[0])];

            return new SqlToken(SqlTokenKind::String, $introducer[0].self::quotedRun($sql, $at + strlen($introducer[0]), $quote, true));
        }

        return null;
    }

    /** A MySQL user or system variable, or null when this `@` opens neither. */
    private static function mysqlVariable(string $sql, int $at): ?string
    {
        $cursor = $at + 1;

        if (($sql[$cursor] ?? '') === '@') {
            $cursor++;
        }

        $first = $sql[$cursor] ?? '';

        if (in_array($first, ["'", '"', '`'], true)) {
            return substr($sql, $at, $cursor - $at).self::quotedRun($sql, $cursor, $first, $first !== '`');
        }

        if (! self::isWordCharacter($first)) {
            return null;
        }

        return substr($sql, $at, $cursor - $at).self::runOf($sql, $cursor, self::isWordCharacter(...));
    }

    /** A block comment including both delimiters, nested where the dialect nests them. */
    private static function blockComment(string $sql, int $at, bool $nests): string
    {
        $length = strlen($sql);
        $depth = 0;
        $cursor = $at;

        while ($cursor < $length) {
            $pair = substr($sql, $cursor, 2);

            if ($pair === '/*' && ($depth === 0 || $nests)) {
                $depth++;
                $cursor += 2;

                continue;
            }

            if ($pair === '*/') {
                $depth--;
                $cursor += 2;

                if ($depth === 0) {
                    return substr($sql, $at, $cursor - $at);
                }

                continue;
            }

            $cursor++;
        }

        return substr($sql, $at);
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
     * upper-case the contents of a string. Where backslash escapes apply, `\'` is the same case.
     */
    private static function quotedRun(string $sql, int $at, string $delimiter, bool $backslashEscapes): string
    {
        $length = strlen($sql);
        $cursor = $at + 1;

        while ($cursor < $length) {
            if ($backslashEscapes && $sql[$cursor] === '\\') {
                $cursor += 2;

                continue;
            }

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
