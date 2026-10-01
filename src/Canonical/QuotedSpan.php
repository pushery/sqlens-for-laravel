<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

use Pushery\SQLens\Contracts\DriverCanonicalization;

/**
 * Where a quoted span ends: a string literal, or a quoted identifier.
 *
 * One answer for every stage that walks a statement, because the stages that each carried their own
 * scanner knew only the doubled delimiter. MySQL also escapes a delimiter with a backslash, and
 * Laravel writes a column comment through `addslashes()`, so `comment 'the setting\'s key'` is ONE
 * literal. A scanner that ended it at `\'` read the rest of the statement as a literal that never
 * closes: the keywords after it stayed lower case, a `PRIMARY KEY` went unseen, and the text inside
 * the literal was rewritten.
 *
 * A backslash escapes only inside a string literal, and only where the driver says so
 * ({@see DriverCanonicalization::usesBackslashStringEscapes()}). Inside a quoted identifier the
 * doubled quote is the only escape on both engines.
 */
final class QuotedSpan
{
    /**
     * One past the closing delimiter of the string literal that opens at $start, or null when it
     * never closes.
     */
    public static function endOfLiteral(string $sql, int $start, string $delimiter, bool $backslashEscapes): ?int
    {
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
}
