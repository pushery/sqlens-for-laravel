<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

use Pushery\SQLens\Contracts\DriverCanonicalization;

/**
 * Where a span ends that the statement's own syntax does not read: a string literal, a quoted
 * identifier, a block comment.
 *
 * One answer for every stage that walks a statement, because the stages that each carried their own
 * scanner knew only the doubled delimiter. MySQL also escapes a delimiter with a backslash, and
 * Laravel writes a column comment through `addslashes()`, so `comment 'the setting\'s key'` is ONE
 * literal. A scanner that ended it at `\'` read the rest of the statement as a literal that never
 * closes: the keywords after it stayed lower case, a `PRIMARY KEY` went unseen, and the text inside
 * the literal was rewritten.
 *
 * A backslash escapes only inside a string literal, and only where the driver says so
 * ({@see DriverCanonicalization::usesBackslashStringEscapes()}) or where the literal is an escape
 * string, `E'…'`, which reads backslash escapes even where plain literals do not. Inside a quoted
 * identifier the doubled quote is the only escape on both engines. A block comment ends at its first
 * closing marker unless the engine nests them ({@see DriverCanonicalization::nestsBlockComments()}).
 */
final class QuotedSpan
{
    /**
     * One past the closing delimiter of the string literal that opens at $start, or null when it
     * never closes.
     */
    public static function endOfLiteral(string $sql, int $start, string $delimiter, bool $backslashEscapes): ?int
    {
        $backslashEscapes = $backslashEscapes || ($delimiter === "'" && self::opensEscapeString($sql, $start));
        $length = strlen($sql);
        $i = $start + 1;

        while ($i < $length) {
            $char = $sql[$i];

            if ($backslashEscapes && $char === '\\') {
                $i += 2;

                continue;
            }

            if ($char === $delimiter) {
                // A doubled delimiter is one escaped character, not a close followed by an open.
                if (($sql[$i + 1] ?? '') === $delimiter) {
                    $i += 2;

                    continue;
                }

                return $i + 1;
            }

            $i++;
        }

        return null;
    }

    /**
     * One past the closing quote of the identifier that opens at $start, or null when it never
     * closes.
     */
    public static function endOfQuotedIdentifier(string $sql, int $start, string $quote): ?int
    {
        return self::endOfLiteral($sql, $start, $quote, false);
    }

    /**
     * One past the marker that closes the block comment opening at $start, or null when it never
     * closes. Where comments nest, every comment opened inside it needs a close of its own.
     */
    public static function endOfBlockComment(string $sql, int $start, bool $nests): ?int
    {
        $length = strlen($sql);
        $depth = 1;
        $i = $start + 2;

        while ($i < $length - 1) {
            $pair = $sql[$i].$sql[$i + 1];

            if ($pair === '*/') {
                $depth--;
                $i += 2;

                if ($depth === 0) {
                    return $i;
                }

                continue;
            }

            if ($nests && $pair === '/*') {
                $depth++;
                $i += 2;

                continue;
            }

            $i++;
        }

        return null;
    }

    /**
     * Whether the quote at $at opens an escape string: a single quote right after a standalone `E`.
     *
     * Standalone means the character before the `E` does not continue a word, so the `E` that ends
     * `ELSE'x'` does not count. On an engine whose plain literals take backslash escapes already,
     * the answer changes nothing.
     */
    private static function opensEscapeString(string $sql, int $at): bool
    {
        if ($at === 0 || strtoupper($sql[$at - 1]) !== 'E') {
            return false;
        }

        return $at === 1 || preg_match('/[A-Za-z0-9_$]/', $sql[$at - 2]) !== 1;
    }
}
