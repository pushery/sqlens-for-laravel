<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical\Stages;

use Pushery\SQLens\Canonical\RawStatement;
use Pushery\SQLens\Contracts\CanonicalizationStage;
use Pushery\SQLens\Contracts\DriverCanonicalization;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * Collapses line breaks, indentation and doubled spaces from the grammar output
 * so two runs that differ only in formatting produce the same canonical form —
 * the precondition for a meaningful later drift comparison.
 *
 * Literal-safe: whitespace INSIDE a string literal, a dollar-quoted body, a
 * comment, or a quoted identifier is kept byte-exact — a default value `'a  b'` is
 * payload, not formatting noise. Line endings are unified (CRLF/CR → LF).
 *
 * This does NOT change keyword casing (that needs a per-driver keyword list and is
 * its own stage), and it is not a pretty-printer (that is the format suite).
 *
 * The literal/comment/dollar-quote/identifier scanning mirrors StatementSplitter;
 * a shared lexer is a later refactor, deliberately not pulled in here to keep each
 * stage independently correct.
 */
final readonly class WhitespaceNormalizer implements CanonicalizationStage
{
    public function __construct(private DriverCanonicalization $driver) {}

    public function __invoke(RawStatement $statement, SubjectContext $context): RawStatement
    {
        return $statement->withSql($this->normalize($statement->sql));
    }

    private function normalize(string $sql): string
    {
        $sql = str_replace(["\r\n", "\r"], "\n", $sql);

        $literals = $this->driver->stringLiteralDelimiters();
        $commentMarkers = $this->driver->commentSyntaxes();
        $lineComments = array_values(array_filter($commentMarkers, static fn (string $marker): bool => $marker !== '/*'));
        $hasBlockComment = in_array('/*', $commentMarkers, true);
        $identifierQuote = $this->driver->quotingCharacter();
        $backslashEscapes = $this->driver->usesBackslashStringEscapes();

        $out = '';
        $length = strlen($sql);
        $i = 0;

        while ($i < $length) {
            $char = $sql[$i];
            $rest = substr($sql, $i);

            if ($this->matchPrefix($rest, $lineComments) !== null) {
                $newline = strpos($sql, "\n", $i);

                if ($newline === false) {
                    $out .= substr($sql, $i);
                    $i = $length;

                    continue;
                }

                // Keep the comment verbatim AND its terminating newline — a line
                // comment runs to end of line, so collapsing that newline to a space
                // would swallow the following statement into the comment. Following
                // whitespace then collapses into the preserved newline.
                $out .= substr($sql, $i, $newline - $i)."\n";
                $i = $newline + 1;
                while ($i < $length && $this->isWhitespace($sql[$i])) {
                    $i++;
                }

                continue;
            }

            if ($hasBlockComment && str_starts_with($rest, '/*')) {
                $close = strpos($sql, '*/', $i + 2);
                $end = $close === false ? $length : $close + 2;
                $out .= substr($sql, $i, $end - $i);
                $i = $end;

                continue;
            }

            if ($this->driver->supportsDollarQuotedStrings() && $char === '$' && preg_match('/\A\$\w*\$/', $rest, $matches) === 1) {
                $tag = $matches[0];
                $close = strpos($sql, $tag, $i + strlen($tag));
                $end = $close === false ? $length : $close + strlen($tag);
                $out .= substr($sql, $i, $end - $i);
                $i = $end;

                continue;
            }

            $literal = $this->matchPrefix($rest, $literals);
            if ($literal !== null) {
                $end = $this->scanQuoted($sql, $i, $literal, $backslashEscapes);
                $end ??= $length;
                $out .= substr($sql, $i, $end - $i);
                $i = $end;

                continue;
            }

            if ($identifierQuote !== '' && $char === $identifierQuote) {
                $end = $this->scanQuoted($sql, $i, $identifierQuote, false) ?? $length;
                $out .= substr($sql, $i, $end - $i);
                $i = $end;

                continue;
            }

            if ($this->isWhitespace($char)) {
                do {
                    $i++;
                } while ($i < $length && $this->isWhitespace($sql[$i]));

                // Collapse the run to a single space, unless it is a leading run or
                // sits right before punctuation that takes no leading space.
                if ($out !== '' && ($i >= $length || ! $this->tightensBefore($sql[$i]))) {
                    $out .= ' ';
                }

                continue;
            }

            $out .= $char;
            $i++;
        }

        return rtrim($out);
    }

    /**
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

    private function scanQuoted(string $sql, int $start, string $quote, bool $backslashEscapes): ?int
    {
        $length = strlen($sql);
        $j = $start + 1;

        while ($j < $length) {
            $char = $sql[$j];

            if ($backslashEscapes && $char === '\\') {
                $j += 2;

                continue;
            }

            if ($char === $quote) {
                if ($j + 1 < $length && $sql[$j + 1] === $quote) {
                    $j += 2;

                    continue;
                }

                return $j + 1;
            }

            $j++;
        }

        return null;
    }

    private function isWhitespace(string $char): bool
    {
        return in_array($char, [' ', "\t", "\n"], true);
    }

    /** Punctuation that takes no space in front of it, so a collapsed run before it is dropped. */
    private function tightensBefore(string $char): bool
    {
        return in_array($char, [',', ';', ')'], true);
    }
}
