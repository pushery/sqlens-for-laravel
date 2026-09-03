<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical\Stages;

use Pushery\SQLens\Canonical\CanonicalizationFailure;
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
 * Not every line of a batch is a statement. A hand-written `.sql` file carries
 * CLIENT directives — `\i other.sql`, `\set ON_ERROR_STOP on` — that psql reads
 * itself and the server never sees. They do not end at a semicolon, so a splitter
 * that ignores them reads the whole file as one enormous statement, silently.
 * {@see self::splitParts()} returns them labeled; {@see self::split()} answers the
 * narrower question and leaves them out.
 */
final class StatementSplitter
{
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
        $directivePrefix = $driver->clientDirectivePrefix();

        $parts = [];
        $current = '';
        $terminator = ';';
        $length = strlen($batch);
        $i = 0;

        while ($i < $length) {
            $char = $batch[$i];
            $rest = substr($batch, $i);

            if ($this->matchPrefix($rest, $lineComments) !== null) {
                $newline = strpos($batch, "\n", $i);
                $end = $newline === false ? $length : $newline;
                $current .= substr($batch, $i, $end - $i);
                $i = $end;

                continue;
            }

            if ($directivePrefix !== ''
                && str_starts_with($rest, $directivePrefix)
                && trim($current) === ''
                && $this->atLineStart($batch, $i)
            ) {
                $newline = strpos($batch, "\n", $i);
                $end = $newline === false ? $length : $newline;

                $parts[] = new StatementPart(trim(substr($batch, $i, $end - $i)), StatementPartKind::ClientDirective);
                $current = '';
                $i = $end;

                continue;
            }

            if ($hasBlockComment && str_starts_with($rest, '/*')) {
                $close = strpos($batch, '*/', $i + 2);
                if ($close === false) {
                    return CanonicalizationFailure::unterminatedLiteral('block comment', $i);
                }

                $current .= substr($batch, $i, $close + 2 - $i);
                $i = $close + 2;

                continue;
            }

            if ($driver->supportsDollarQuotedStrings() && $char === '$' && preg_match('/\A\$\w*\$/', $rest, $matches) === 1) {
                $tag = $matches[0];
                $close = strpos($batch, $tag, $i + strlen($tag));
                if ($close === false) {
                    return CanonicalizationFailure::unterminatedLiteral('dollar-quoted string', $i);
                }

                $end = $close + strlen($tag);
                $current .= substr($batch, $i, $end - $i);
                $i = $end;

                continue;
            }

            $literal = $this->matchPrefix($rest, $literals);
            if ($literal !== null) {
                $end = $this->scanQuoted($batch, $i, $literal, $backslashEscapes);
                if ($end === null) {
                    return CanonicalizationFailure::unterminatedLiteral('string literal', $i);
                }

                $current .= substr($batch, $i, $end - $i);
                $i = $end;

                continue;
            }

            if ($identifierQuote !== '' && $char === $identifierQuote) {
                $end = $this->scanQuoted($batch, $i, $identifierQuote, false);
                if ($end === null) {
                    return CanonicalizationFailure::unterminatedLiteral('quoted identifier', $i);
                }

                $current .= substr($batch, $i, $end - $i);
                $i = $end;

                continue;
            }

            if ($driver->supportsDelimiterRedefinition() && trim($current) === '' && preg_match('/\ADELIMITER\s+/i', $rest) === 1) {
                [$newTerminator, $consumed] = $this->readDelimiter($batch, $i);
                if ($newTerminator === '') {
                    return CanonicalizationFailure::unknownDelimiterSituation('a DELIMITER statement declares no new delimiter', $i);
                }

                $terminator = $newTerminator;
                $current = '';
                $i += $consumed;

                continue;
            }

            if (str_starts_with($rest, $terminator)) {
                $trimmed = trim($current);
                if ($trimmed !== '') {
                    $parts[] = new StatementPart($trimmed, StatementPartKind::Sql);
                }

                $current = '';
                $i += strlen($terminator);

                continue;
            }

            $current .= $char;
            $i++;
        }

        $trailing = trim($current);
        if ($trailing !== '') {
            $parts[] = new StatementPart($trailing, StatementPartKind::Sql);
        }

        return $parts;
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
     * The first candidate that prefixes the haystack, or null.
     *
     * @param  list<string>  $candidates
     */
    private function matchPrefix(string $haystack, array $candidates): ?string
    {
        foreach ($candidates as $candidate) {
            if ($candidate !== '' && str_starts_with($haystack, $candidate)) {
                return $candidate;
            }
        }

        return null;
    }

    /**
     * Scan a single-character-quoted region from its opening quote at $start to the
     * matching close, honoring doubled quotes and (when enabled) backslash
     * escapes. Returns the index just past the closing quote, or null if it is
     * never closed.
     */
    private function scanQuoted(string $batch, int $start, string $quote, bool $backslashEscapes): ?int
    {
        $length = strlen($batch);
        $j = $start + 1;

        while ($j < $length) {
            $char = $batch[$j];

            if ($backslashEscapes && $char === '\\') {
                $j += 2;

                continue;
            }

            if ($char === $quote) {
                if ($j + 1 < $length && $batch[$j + 1] === $quote) {
                    $j += 2; // a doubled quote is an escaped quote, still inside

                    continue;
                }

                return $j + 1;
            }

            $j++;
        }

        return null;
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
