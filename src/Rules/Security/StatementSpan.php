<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

/**
 * A statement a finding hands to the reader, set as a code span of its own.
 *
 * The span is what separates the statement from the sentence around it: without it, a reader
 * copying "… and REVOKE SELECT ON TABLE "public"."orders" FROM PUBLIC if not." takes the words
 * after it along, and a Markdown renderer eats the quotes. A MySQL statement quotes its names in
 * backticks, so its span is opened with two and padded, the only form a backtick inside can survive.
 */
final readonly class StatementSpan
{
    public static function of(string $statement): string
    {
        return str_contains($statement, '`') ? '`` '.$statement.' ``' : '`'.$statement.'`';
    }

    /**
     * The statement with its names filled in, in its span, or its shape with `…` for the names.
     *
     * The names are the quoted forms a reader wrote. When one of them could not be written, the
     * shape is still worth saying, and a statement completed with an unquoted name would be the
     * very thing the quoting exists to prevent.
     */
    public static function naming(string $statement, string ...$names): string
    {
        if (in_array('', $names, true)) {
            return str_replace('%s', '…', $statement);
        }

        return self::of(sprintf($statement, ...$names));
    }
}
