<?php

declare(strict_types=1);

namespace Pushery\SQLens\Patterns;

use Pushery\SQLens\Canonical\Extensions\CanonicalExtensionRegistry;
use Pushery\SQLens\Canonical\QuotedSpan;
use Pushery\SQLens\Canonical\ScanAt;
use Pushery\SQLens\Canonical\StringLiteralMask;
use Pushery\SQLens\Contracts\Driver;
use Pushery\SQLens\Contracts\DriverCanonicalization;
use Pushery\SQLens\Drivers\DriverManager;
use Throwable;

/**
 * The pattern of a statement a connection ran, for grouping the queries of a request.
 *
 * ## What a pattern keeps and what it takes out
 *
 * Every value becomes `?`: a string literal, a number, a typed literal such as `DATE '2024-01-01'`
 * or `INTERVAL '1 day'`, a literal with a prefix or an introducer (`N'…'`, `E'…'`, `X'…'`,
 * `_utf8mb4'…'`), a dollar-quoted string, and every placeholder, whether `?`, `$1` or `:name`. A list
 * of values is one value however long it is, so `IN (?, ?, ?)` and `IN (1)` are both `IN (?)`, and an
 * insert of three rows has the pattern of an insert of one. Comments go, unquoted words fold to
 * lower case, and whitespace becomes single spaces. Quoted names stay as written.
 *
 * Unquoted words fold on both engines. PostgreSQL folds them itself; MySQL keeps the case of a table
 * name on some platforms, so there a pattern does not tell `Users` from `users`. A pattern groups
 * statements by their shape, and that is the grouping a request's queries are read by.
 *
 * ## Where a literal ends is the engine's answer
 *
 * The walk asks the connection's grammar, as {@see StringLiteralMask} does: which quotes open a
 * literal, whether a backslash escapes one, which markers open a comment, and whether dollar quotes
 * exist. A connection whose engine registered no grammar gets {@see StringLiteralMask::coarse()}:
 * everything from the first quote to the last is one masked span, because any other reading can end
 * a literal early and keep the rest of it as text. Such a pattern says so in `coarse`.
 *
 * Nothing it reads depends on the locale, so the same statement has the same pattern on every
 * machine.
 *
 * ## What it never does
 *
 * It opens no connection, it never carries a value into the pattern, and it does not throw for a
 * statement it cannot read: a literal that never closes is masked to the end.
 */
final readonly class QueryPatterns
{
    /** The bytes SQL reads as whitespace. Listed rather than asked of `ctype_space()`, which answers by the locale. */
    private const string WHITESPACE = " \t\n\r\v\f";

    /** The words that make the string literal after them a value of their type. */
    private const array TYPED_LITERALS = ['date', 'time', 'timestamp', 'interval'];

    /** The prefixes written against a quote that belong to the literal: national, escape, hexadecimal and bit strings. */
    private const array LITERAL_PREFIXES = ['n', 'e', 'x', 'b'];

    /** What stands before a sign that belongs to the number after it, where it cannot be an operator. */
    private const array OPERAND_OPENERS = [
        '(', ',', '=', '<', '>', '!', '*', '/', '%', '+', '-', '|',
        'and', 'or', 'not', 'between', 'when', 'then', 'else', 'select', 'values',
    ];

    /** Unit separator: a byte no pattern contains, so the fields of a fingerprint cannot bleed together. */
    private const string UNIT = "\x1f";

    public function __construct(
        private CanonicalExtensionRegistry $grammars,
        private DriverManager $drivers,
    ) {}

    /** The pattern of a statement that ran on the named connection. */
    public function of(string $sql, string $connection): QueryPattern
    {
        [$engine, $grammar] = $this->grammarOf($connection);
        $coarse = ! $grammar instanceof DriverCanonicalization;
        $pattern = $this->render($coarse ? $this->tokens(StringLiteralMask::coarse($sql), null) : $this->tokens($sql, $grammar));

        return new QueryPattern(
            $pattern,
            hash('sha256', implode(self::UNIT, ['p'.QueryPattern::VERSION, $engine ?? '', $coarse ? 'coarse' : 'grammar', $pattern])),
            $coarse,
        );
    }

    /**
     * The connection's engine and its grammar, or null for either where it has none.
     *
     * @return array{0: ?string, 1: ?DriverCanonicalization}
     */
    private function grammarOf(string $connection): array
    {
        $driver = $this->drivers->resolve($connection);

        if (! $driver instanceof Driver) {
            return [null, null];
        }

        return [$driver->key(), $this->grammarFor($driver->key())];
    }

    /**
     * The grammar an engine registered, or null where it registered none or it fails to build.
     *
     * Caught rather than trusted: a third party's canonicalization can throw while it is built, and
     * the coarse mask is the answer that stays correct without one.
     */
    private function grammarFor(string $engine): ?DriverCanonicalization
    {
        try {
            $grammar = $this->grammars->forDriver($engine);
        } catch (Throwable) {
            return null;
        }

        return $grammar instanceof DriverCanonicalization ? $grammar : null;
    }

    /**
     * The statement as tokens with every value already `?`, each with whether whitespace or a
     * comment stood before it.
     *
     * @return list<array{0: string, 1: bool}>
     */
    private function tokens(string $sql, ?DriverCanonicalization $grammar): array
    {
        $delimiters = $grammar?->stringLiteralDelimiters() ?? [];
        $backslashEscapes = $grammar?->usesBackslashStringEscapes() ?? false;
        $identifierQuote = $grammar?->quotingCharacter() ?? '';
        $markers = $grammar?->commentSyntaxes() ?? [];
        $lineComments = array_values(array_filter($markers, static fn (string $marker): bool => $marker !== '/*'));
        $blockComments = in_array('/*', $markers, true);
        $nestsComments = $grammar?->nestsBlockComments() ?? false;
        $dollarQuotes = $grammar?->supportsDollarQuotedStrings() ?? false;

        /** @var list<array{0: string, 1: bool}> $tokens */
        $tokens = [];
        $spaced = false;
        $length = strlen($sql);
        $i = 0;

        while ($i < $length) {
            $char = $sql[$i];

            if (str_contains(self::WHITESPACE, $char)) {
                $spaced = true;
                $i++;

                continue;
            }

            // A comment says nothing about the statement's shape, and one that carries a request id
            // would split one pattern into as many as there are requests.
            if (ScanAt::firstOf($sql, $i, $lineComments) !== null) {
                $newline = strpos($sql, "\n", $i);
                $i = $newline === false ? $length : $newline;
                $spaced = true;

                continue;
            }

            if ($blockComments && ScanAt::startsWith($sql, $i, '/*')) {
                $i = QuotedSpan::endOfBlockComment($sql, $i, $nestsComments) ?? $length;
                $spaced = true;

                continue;
            }

            if ($dollarQuotes && $char === '$' && preg_match('/\G\$[0-9]+/', $sql, $parameter, 0, $i) === 1) {
                $this->push($tokens, $spaced, '?');
                $i += strlen($parameter[0]);

                continue;
            }

            if ($dollarQuotes && $char === '$' && preg_match('/\G\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/', $sql, $tag, 0, $i) === 1) {
                $close = strpos($sql, $tag[0], $i + strlen($tag[0]));
                $i = $close === false ? $length : $close + strlen($tag[0]);
                $this->literal($tokens, $spaced);

                continue;
            }

            $identifierEnd = $identifierQuote !== '' && $char === $identifierQuote ? QuotedSpan::endOfQuotedIdentifier($sql, $i, $char) : null;

            // A quoted name is copied whole: what it holds is a name, and a quote or a comma inside it
            // is part of that name. One that never closes copies its quote, and the walk goes on.
            if ($identifierEnd !== null) {
                $this->push($tokens, $spaced, substr($sql, $i, $identifierEnd - $i));
                $i = $identifierEnd;

                continue;
            }

            if (in_array($char, $delimiters, true)) {
                $i = QuotedSpan::endOfLiteral($sql, $i, $char, $backslashEscapes) ?? $length;
                $this->literal($tokens, $spaced);

                continue;
            }

            if ($char === '?') {
                // PDO reads `??` as one question mark that is an operator, the way PostgreSQL's JSON
                // operators are written in a prepared statement.
                $operator = ($sql[$i + 1] ?? '') === '?';
                $this->push($tokens, $spaced, $operator ? '??' : '?');
                $i += $operator ? 2 : 1;

                continue;
            }

            // A named placeholder, `:name`, and never the second colon of a cast or a slice bound.
            if ($char === ':' && preg_match('/[A-Za-z0-9_$:\])]/', $i === 0 ? ' ' : $sql[$i - 1]) !== 1 && preg_match('/\G:[A-Za-z_][A-Za-z0-9_]*/', $sql, $name, 0, $i) === 1) {
                $this->push($tokens, $spaced, '?');
                $i += strlen($name[0]);

                continue;
            }

            if (preg_match('/\G[A-Za-z_\x80-\xff][A-Za-z0-9_$\x80-\xff]*/', $sql, $word, 0, $i) === 1) {
                $this->push($tokens, $spaced, strtolower($word[0]));
                $i += strlen($word[0]);

                continue;
            }

            // A number, and never the digits that begin a MySQL name such as `1st_quarter`.
            if (preg_match('/\G(?:0[xX][0-9A-Fa-f]+|0[bB][01]+|(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)(?![A-Za-z0-9_$\x80-\xff])/', $sql, $number, 0, $i) === 1) {
                $this->number($tokens, $spaced);
                $i += strlen($number[0]);

                continue;
            }

            $this->push($tokens, $spaced, $char);
            $i++;
        }

        return $tokens;
    }

    /**
     * @param  list<array{0: string, 1: bool}>  $tokens
     *
     * @param-out list<array{0: string, 1: bool}> $tokens
     */
    private function push(array &$tokens, bool &$spaced, string $text): void
    {
        $tokens[] = [$text, $spaced];
        $spaced = false;
    }

    /**
     * A string literal as one value, with what belongs to it: a prefix or an introducer written
     * against its quote, and a type word before it.
     *
     * @param  list<array{0: string, 1: bool}>  $tokens
     *
     * @param-out list<array{0: string, 1: bool}> $tokens
     */
    private function literal(array &$tokens, bool &$spaced): void
    {
        $last = $tokens[count($tokens) - 1] ?? null;
        $before = $tokens[count($tokens) - 2] ?? null;

        if (! $spaced && $last !== null && (in_array($last[0], self::LITERAL_PREFIXES, true) || preg_match('/^_[a-z0-9_]+$/', $last[0]) === 1)) {
            $spaced = $last[1];
            $tokens = array_slice($tokens, 0, -1);
        } elseif (! $spaced && $last !== null && $before !== null && $last[0] === '&' && ! $last[1] && $before[0] === 'u') {
            // U&'…', PostgreSQL's string with Unicode escapes.
            $spaced = $before[1];
            $tokens = array_slice($tokens, 0, -2);
        }

        $last = $tokens[count($tokens) - 1] ?? null;

        if ($last !== null && in_array($last[0], self::TYPED_LITERALS, true)) {
            $spaced = $last[1];
            $tokens = array_slice($tokens, 0, -1);
        }

        $this->push($tokens, $spaced, '?');
    }

    /**
     * A number as one value, with the sign written against it where the sign cannot be an operator.
     *
     * @param  list<array{0: string, 1: bool}>  $tokens
     *
     * @param-out list<array{0: string, 1: bool}> $tokens
     */
    private function number(array &$tokens, bool &$spaced): void
    {
        $sign = $tokens[count($tokens) - 1] ?? null;
        $before = $tokens[count($tokens) - 2] ?? null;

        if (! $spaced && $sign !== null && in_array($sign[0], ['-', '+'], true) && ($before === null || in_array($before[0], self::OPERAND_OPENERS, true))) {
            $spaced = $sign[1];
            $tokens = array_slice($tokens, 0, -1);
        }

        $this->push($tokens, $spaced, '?');
    }

    /**
     * The tokens as one line: every list of values reduced to one, a closing semicolon dropped, and
     * one space wherever the statement had whitespace or a comment, none inside parentheses or before
     * a comma, and one after a comma.
     *
     * @param  list<array{0: string, 1: bool}>  $tokens
     */
    private function render(array $tokens): string
    {
        $tokens = $this->collapsed($tokens);

        while ($tokens !== [] && $tokens[count($tokens) - 1][0] === ';') {
            $tokens = array_slice($tokens, 0, -1);
        }

        $out = '';
        $previous = null;

        foreach ($tokens as [$text, $spaced]) {
            $space = $previous !== null && match (true) {
                $previous === '(', $text === ')', $text === ',' => false,
                $previous === ',' => true,
                default => $spaced,
            };
            $out .= ($space ? ' ' : '').$text;
            $previous = $text;
        }

        return $out;
    }

    /**
     * A parenthesized list of values as one value, and the rows after `VALUES` as one row: `IN (?, ?, ?)`
     * becomes `IN (?)`, and `VALUES (?, ?), (?, ?)` becomes `VALUES (?)`.
     *
     * Only a list that holds nothing but values collapses. A value at the end of one expression and
     * one at the start of the next are separated by a comma as well, `- ?, ?+?`, and folding those
     * would join two expressions into one.
     *
     * @param  list<array{0: string, 1: bool}>  $tokens
     * @return list<array{0: string, 1: bool}>
     */
    private function collapsed(array $tokens): array
    {
        $lists = [];
        $count = count($tokens);

        for ($i = 0; $i < $count; $i++) {
            $close = $tokens[$i][0] === '(' ? $this->closeOfValueList($tokens, $i) : null;

            if ($close !== null) {
                $lists[] = $tokens[$i];
                $lists[] = $tokens[$i + 1];
                $lists[] = $tokens[$close];
                $i = $close;

                continue;
            }

            $lists[] = $tokens[$i];
        }

        $rows = [];
        $count = count($lists);

        for ($i = 0; $i < $count; $i++) {
            $rows[] = $lists[$i];

            if (! in_array($lists[$i][0], ['values', 'value'], true) || ! $this->isOneValue($lists, $i + 1)) {
                continue;
            }
            $rows[] = $lists[$i + 1];
            $rows[] = $lists[$i + 2];
            $rows[] = $lists[$i + 3];
            $next = $i + 4;

            while (($lists[$next][0] ?? null) === ',' && $this->isOneValue($lists, $next + 1)) {
                $next += 4;
            }

            $i = $next - 1;
        }

        return $rows;
    }

    /**
     * Where the list of values that the parenthesis at $open begins is closed, or null where what
     * it holds is not values alone.
     *
     * @param  list<array{0: string, 1: bool}>  $tokens
     */
    private function closeOfValueList(array $tokens, int $open): ?int
    {
        $at = $open + 1;

        if (($tokens[$at][0] ?? null) !== '?') {
            return null;
        }

        while (($tokens[$at + 1][0] ?? null) === ',' && ($tokens[$at + 2][0] ?? null) === '?') {
            $at += 2;
        }

        return ($tokens[$at + 1][0] ?? null) === ')' ? $at + 1 : null;
    }

    /**
     * Whether `(?)` begins at $at.
     *
     * @param  list<array{0: string, 1: bool}>  $tokens
     */
    private function isOneValue(array $tokens, int $at): bool
    {
        return ($tokens[$at][0] ?? null) === '(' && ($tokens[$at + 1][0] ?? null) === '?' && ($tokens[$at + 2][0] ?? null) === ')';
    }
}
