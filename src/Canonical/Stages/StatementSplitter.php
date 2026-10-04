<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical\Stages;

use Pushery\SQLens\Canonical\CanonicalizationFailure;
use Pushery\SQLens\Canonical\QuotedSpan;
use Pushery\SQLens\Canonical\ScanAt;
use Pushery\SQLens\Canonical\StatementPart;
use Pushery\SQLens\Canonical\StatementPartKind;
use Pushery\SQLens\Contracts\DriverCanonicalization;

/**
 * Turns a raw SQL batch into the stable unit "one statement" that every rule and
 * every later evidence pointer refers to. A single blueprint call can emit
 * several statements (a column plus its index, a `->change()`), so multi-statement
 * batches are the normal case, not the exception — this is the one place that
 * bundling is resolved into deterministically ordered single statements.
 *
 * Splitting happens once, centrally: no rule may later split on a semicolon
 * itself. It is literal-, comment-, dollar-quote- and DELIMITER-safe, and all the
 * syntax comes from the driver extension point — never a constant baked into the
 * core. The returned list is in execution order (its index is the statement's
 * order within the batch); the source file is attached by the caller.
 *
 * Three-valued: input that cannot be split safely — an unterminated literal, a
 * malformed DELIMITER, or a driver that declares no literal/comment syntax —
 * yields a named CanonicalizationFailure, never a silent, wrong tokenization.
 *
 * A string literal, quoted identifier and driver delimiter are all single
 * characters here (as PostgreSQL and MySQL declare them).
 *
 * A stored routine is ONE statement however many semicolons its body holds.
 * `CREATE TRIGGER … BEGIN …; …; END` reaches the server in one piece, so a `;`
 * inside a `BEGIN … END` block of a routine definition, a PostgreSQL
 * `BEGIN ATOMIC` body included, does not end the statement. Only the default
 * terminator is read this way: after `DELIMITER`, the batch delimits its bodies
 * itself.
 *
 * Not every line of a batch is a statement. A hand-written `.sql` file carries
 * CLIENT directives — `\i other.sql`, `\set ON_ERROR_STOP on` — that psql reads
 * itself and the server never sees. They do not end at a semicolon, so a splitter
 * that ignores them reads the whole file as one enormous statement, silently.
 * {@see self::splitParts()} returns them labeled; {@see self::split()} answers the
 * narrower question and leaves them out.
 */
final class StatementSplitter
{
    /** The characters a keyword or an unquoted identifier is made of. */
    private const string WORD_CHARACTERS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$';

    /** The words after `END` that close a construct whose opening is not counted. */
    private const array UNCOUNTED_CLOSINGS = ['IF', 'LOOP', 'WHILE', 'REPEAT'];

    /**
     * The SQL statements in the batch, in execution order.
     *
     * A client directive is not one and is dropped here on purpose: this answer feeds the
     * canonicalization, where `\i other.sql` is noise — it never reaches a server, so no rule can
     * have an opinion about it. A caller that has to write the file BACK asks {@see self::splitParts()}
     * instead and keeps every line.
     *
     * @return list<string>|CanonicalizationFailure
     */
    public function split(string $batch, DriverCanonicalization $driver): array|CanonicalizationFailure
    {
        $parts = $this->splitParts($batch, $driver);

        if ($parts instanceof CanonicalizationFailure) {
            return $parts;
        }

        return array_values(array_map(
            static fn (StatementPart $part): string => $part->text,
            array_filter($parts, static fn (StatementPart $part): bool => $part->isSql()),
        ));
    }

    /**
     * Every piece of the batch, in file order, each saying what it is.
     *
     * One walk answers both questions. Two would be two tokenizers over the same dollar-quoted
     * bodies and DELIMITER changes, free to disagree about where one ends — which is exactly the
     * "no rule splits on a semicolon itself" rule this class exists to enforce, broken from the
     * inside.
     *
     * @return list<StatementPart>|CanonicalizationFailure
     */
    public function splitParts(string $batch, DriverCanonicalization $driver): array|CanonicalizationFailure
    {
        $literals = $driver->stringLiteralDelimiters();
        $commentMarkers = $driver->commentSyntaxes();

        if ($literals === [] || $commentMarkers === []) {
            return CanonicalizationFailure::missingSplitSyntax();
        }

        $lineComments = array_values(array_filter($commentMarkers, static fn (string $marker): bool => $marker !== '/*'));
        $hasBlockComment = in_array('/*', $commentMarkers, true);
        $identifierQuote = $driver->quotingCharacter();
        $backslashEscapes = $driver->usesBackslashStringEscapes();
        $nestedComments = $driver->nestsBlockComments();
        $directivePrefix = $driver->clientDirectivePrefix();

        $parts = [];
        $current = '';
        // Whether the statement read so far holds anything but comments and blank space. A directive
        // and a `DELIMITER` line are read only before it does, and a comment in front of either
        // leaves it false: a comment is not statement content.
        $hasSql = false;
        $terminator = ';';
        $length = strlen($batch);
        $i = 0;
        // How many `BEGIN`/`CASE` blocks of a routine body are open at $i. A `;` inside one belongs
        // to the body.
        $depth = 0;

        while ($i < $length) {
            $char = $batch[$i];

            if (ScanAt::firstOf($batch, $i, $lineComments) !== null) {
                $newline = strpos($batch, "\n", $i);
                $end = $newline === false ? $length : $newline;
                $current .= substr($batch, $i, $end - $i);
                $i = $end;

                continue;
            }

            if ($directivePrefix !== ''
                && ! $hasSql
                && ScanAt::startsWith($batch, $i, $directivePrefix)
                && $this->atLineStart($batch, $i)
            ) {
                $newline = strpos($batch, "\n", $i);
                $end = $newline === false ? $length : $newline;

                $parts[] = new StatementPart(trim(substr($batch, $i, $end - $i)), StatementPartKind::ClientDirective);
                $current = '';
                $i = $end;

                continue;
            }

            if ($hasBlockComment && ScanAt::startsWith($batch, $i, '/*')) {
                $end = QuotedSpan::endOfBlockComment($batch, $i, $nestedComments);
                if ($end === null) {
                    return CanonicalizationFailure::unterminatedLiteral('block comment', $i);
                }

                $current .= substr($batch, $i, $end - $i);
                $i = $end;

                continue;
            }

            if ($driver->supportsDollarQuotedStrings() && $char === '$' && preg_match('/\G\$\w*\$/', $batch, $matches, 0, $i) === 1) {
                $tag = $matches[0];
                $close = strpos($batch, $tag, $i + strlen($tag));
                if ($close === false) {
                    return CanonicalizationFailure::unterminatedLiteral('dollar-quoted string', $i);
                }

                $end = $close + strlen($tag);
                $current .= substr($batch, $i, $end - $i);
                $hasSql = true;
                $i = $end;

                continue;
            }

            $literal = ScanAt::firstOf($batch, $i, $literals);
            if ($literal !== null) {
                $end = QuotedSpan::endOfLiteral($batch, $i, $literal, $backslashEscapes);
                if ($end === null) {
                    return CanonicalizationFailure::unterminatedLiteral('string literal', $i);
                }

                $current .= substr($batch, $i, $end - $i);
                $hasSql = true;
                $i = $end;

                continue;
            }

            if ($identifierQuote !== '' && $char === $identifierQuote) {
                $end = QuotedSpan::endOfQuotedIdentifier($batch, $i, $identifierQuote);
                if ($end === null) {
                    return CanonicalizationFailure::unterminatedLiteral('quoted identifier', $i);
                }

                $current .= substr($batch, $i, $end - $i);
                $hasSql = true;
                $i = $end;

                continue;
            }

            if (! $hasSql && $driver->supportsDelimiterRedefinition() && preg_match('/\GDELIMITER\s+/i', $batch, offset: $i) === 1) {
                [$newTerminator, $consumed] = $this->readDelimiter($batch, $i);
                if ($newTerminator === '') {
                    return CanonicalizationFailure::unknownDelimiterSituation('a DELIMITER statement declares no new delimiter', $i);
                }

                $terminator = $newTerminator;
                $current = '';
                $i += $consumed;

                continue;
            }

            if ($terminator === ';' && $this->wordStartsAt($batch, $i)) {
                $word = substr($batch, $i, strspn($batch, self::WORD_CHARACTERS, $i));
                [$depth, $consumed] = $this->blockStep($batch, $i, $word, $depth, $current);

                $current .= substr($batch, $i, $consumed);
                $hasSql = true;
                $i += $consumed;

                continue;
            }

            if ($depth > 0 && ScanAt::startsWith($batch, $i, $terminator)) {
                $current .= $terminator;
                $i += strlen($terminator);

                continue;
            }

            if (ScanAt::startsWith($batch, $i, $terminator)) {
                $trimmed = trim($current);
                if ($trimmed !== '') {
                    $parts[] = new StatementPart($trimmed, StatementPartKind::Sql);
                }

                $current = '';
                $hasSql = false;
                $i += strlen($terminator);

                continue;
            }

            $current .= $char;
            $hasSql = $hasSql || ! ctype_space($char);
            $i++;
        }

        $trailing = trim($current);
        if ($trailing !== '') {
            $parts[] = new StatementPart($trailing, StatementPartKind::Sql);
        }

        return $parts;
    }

    /**
     * Whether a keyword or an unquoted identifier starts at $at: a letter or an underscore that does
     * not continue a word, so `xbegin` and `1e10` are not read as `begin` or `e10`.
     */
    private function wordStartsAt(string $batch, int $at): bool
    {
        $char = $batch[$at];

        if (! ctype_alpha($char) && $char !== '_') {
            return false;
        }

        return $at === 0 || strspn($batch[$at - 1], self::WORD_CHARACTERS) === 0;
    }

    /**
     * The block depth after one word, and how many bytes of the batch the step takes.
     *
     * Opening: `BEGIN` in a statement that defines a routine or inside a block already open, where
     * a transaction's `BEGIN` cannot stand; `CASE` inside a block, because it ends with an `END` of
     * its own. Closing: `END`, and `END CASE` as one closing. `END IF`, `END LOOP`, `END WHILE` and
     * `END REPEAT` close constructs whose opening words are not counted, because `IF` is also a
     * function and part of `IF EXISTS`. An `END` with no block open is left alone: it is a word
     * that happens to be spelled that way.
     *
     * @return array{int, int}
     */
    private function blockStep(string $batch, int $at, string $word, int $depth, string $current): array
    {
        $length = strlen($word);

        return match (strtoupper($word)) {
            'BEGIN' => [$depth > 0 || $this->definesARoutine($current) ? $depth + 1 : $depth, $length],
            'CASE' => [$depth > 0 ? $depth + 1 : $depth, $length],
            'END' => $depth > 0 ? $this->closing($batch, $at + $length, $depth, $length) : [$depth, $length],
            default => [$depth, $length],
        };
    }

    /**
     * What an `END` inside a block closes, from the word that follows it.
     *
     * @return array{int, int}
     */
    private function closing(string $batch, int $after, int $depth, int $length): array
    {
        $gap = strspn($batch, " \t\r\n", $after);
        $next = strtoupper(substr($batch, $after + $gap, strspn($batch, self::WORD_CHARACTERS, $after + $gap)));

        if (in_array($next, self::UNCOUNTED_CLOSINGS, true)) {
            return [$depth, $length];
        }

        // `END CASE` is one closing, so its CASE is taken along and cannot open another block.
        return $next === 'CASE'
            ? [$depth - 1, $length + $gap + strlen($next)]
            : [$depth - 1, $length];
    }

    /**
     * Whether the statement read so far defines a stored routine: a trigger, a procedure, a function
     * or an event, the statements whose body may hold a block.
     */
    private function definesARoutine(string $current): bool
    {
        return preg_match('/\A(?:\s+|--[^\n]*\n|#[^\n]*\n|\/\*.*?\*\/)*CREATE\b.*?\b(?:TRIGGER|PROCEDURE|FUNCTION|EVENT)\b/is', $current) === 1;
    }

    /**
     * Whether $at is the first non-blank position on its line.
     *
     * The directive rule is deliberately NARROWER than psql's, which accepts a backslash command
     * anywhere it is not inside a literal — including after a semicolon on the same line. The two
     * ways to be wrong here are not symmetric: reading a directive as SQL is what happens today and
     * costs a bad split, while reading SQL as a directive silently DELETES a statement from the
     * batch. So the stricter rule wins, and it is the one the ticket asked for: after optional
     * whitespace, at the start of a line.
     */
    private function atLineStart(string $batch, int $at): bool
    {
        for ($back = $at - 1; $back >= 0; $back--) {
            if ($batch[$back] === "\n") {
                return true;
            }

            if (! in_array($batch[$back], [' ', "\t", "\r"], true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Read a `DELIMITER <x>` line from $start. Returns the new delimiter (empty if
     * none is declared) and how many characters to consume, including the newline.
     *
     * @return array{string, int}
     */
    private function readDelimiter(string $batch, int $start): array
    {
        $newline = strpos($batch, "\n", $start);
        $lineEnd = $newline === false ? strlen($batch) : $newline;
        $line = substr($batch, $start, $lineEnd - $start);
        $delimiter = trim(substr($line, strlen('DELIMITER')));
        $consumed = ($lineEnd - $start) + ($newline === false ? 0 : 1);

        return [$delimiter, $consumed];
    }
}
