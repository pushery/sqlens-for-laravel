<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

/**
 * Whether a statement continues with a given text at a given position, asked in place.
 *
 * The scanners walk a statement one character at a time. Asking "does the text from here start
 * with X" by first copying the rest of the input (`substr($sql, $i)`) copied it again at every
 * character, so the walk cost grew with the square of the input's length: splitting a 1.1 MB
 * schema dump took over two seconds, where a walk that compares in place stays linear.
 */
final class ScanAt
{
    /** Whether $sql continues with $prefix at $at. An empty prefix never matches. */
    public static function startsWith(string $sql, int $at, string $prefix): bool
    {
        return $prefix !== '' && substr_compare($sql, $prefix, $at, strlen($prefix)) === 0;
    }

    /**
     * The first of $candidates that $sql continues with at $at, or null.
     *
     * @param  list<string>  $candidates
     */
    public static function firstOf(string $sql, int $at, array $candidates): ?string
    {
        // The first character decides almost every position before a comparison is needed: the
        // walk asks this at every character, and most characters open nothing.
        $char = $sql[$at] ?? '';

        foreach ($candidates as $candidate) {
            if ($candidate !== '' && $candidate[0] === $char && self::startsWith($sql, $at, $candidate)) {
                return $candidate;
            }
        }

        return null;
    }
}
