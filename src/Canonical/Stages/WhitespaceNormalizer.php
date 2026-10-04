<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical\Stages;

use Pushery\SQLens\Canonical\QuotedSpan;
use Pushery\SQLens\Canonical\RawStatement;
use Pushery\SQLens\Canonical\ScanAt;
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
        $nestedComments = $this->driver->nestsBlockComments();

        $out = '';
        $length = strlen($sql);
        $i = 0;

        while ($i < $length) {
            $char = $sql[$i];

            if (ScanAt::firstOf($sql, $i, $lineComments) !== null) {
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

            if ($hasBlockComment && ScanAt::startsWith($sql, $i, '/*')) {
                $end = QuotedSpan::endOfBlockComment($sql, $i, $nestedComments) ?? $length;
                $out .= substr($sql, $i, $end - $i);
                $i = $end;

                continue;
            }

            if ($this->driver->supportsDollarQuotedStrings() && $char === '$' && preg_match('/\G\$\w*\$/', $sql, $matches, 0, $i) === 1) {
                $tag = $matches[0];
                $close = strpos($sql, $tag, $i + strlen($tag));
                $end = $close === false ? $length : $close + strlen($tag);
                $out .= substr($sql, $i, $end - $i);
                $i = $end;

                continue;
            }

            $literal = ScanAt::firstOf($sql, $i, $literals);
            if ($literal !== null) {
                $end = QuotedSpan::endOfLiteral($sql, $i, $literal, $backslashEscapes) ?? $length;
                $out .= substr($sql, $i, $end - $i);
                $i = $end;

                continue;
            }

            if ($identifierQuote !== '' && $char === $identifierQuote) {
                $end = QuotedSpan::endOfQuotedIdentifier($sql, $i, $identifierQuote) ?? $length;
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
