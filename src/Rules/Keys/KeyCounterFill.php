<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Keys;

/**
 * How much of its ceiling a primary key has used, from the counter the audit read beside the catalog.
 *
 * Shared by the two near-ceiling rules for the reason {@see NarrowIntegerPrimaryKey} is shared: the
 * arithmetic is the same on both engines, and two copies would drift on exactly the numbers a reader
 * checks before trusting the rest of the finding.
 */
final readonly class KeyCounterFill
{
    /**
     * The share of its ceiling a key may use before it is reported, unless the project sets another.
     *
     * Half: the point at which the key has handed out as many values as it has left. At the rate that
     * brought it there, the room that remains lasts as long as the table has existed so far, and the
     * insert rate of a growing table rarely stays where it was.
     */
    public const int DEFAULT_MIN_PERCENT_USED = 50;

    /**
     * The largest value of an integer column type, as an int.
     *
     * Null for an unsigned `bigint`, whose ceiling PHP's integer cannot hold, and for a type this
     * class does not know: a caller then says nothing about a limit rather than a wrong one.
     */
    public static function columnCeiling(string $type, bool $unsigned): ?int
    {
        $type = strtolower($type);

        if ($type === 'bigint') {
            return $unsigned ? null : PHP_INT_MAX;
        }

        $row = NarrowIntegerPrimaryKey::CEILING[$type] ?? null;

        if ($row === null) {
            return null;
        }

        return $unsigned ? $row['unsigned'] : $row['signed'];
    }

    /** Whether a key that has used this many of its values has reached the share. */
    public static function reaches(int $used, int $ceiling, int $minPercentUsed): bool
    {
        return $ceiling > 0 && $used / $ceiling * 100 >= $minPercentUsed;
    }

    /**
     * The share as a finding prints it, to one decimal.
     *
     * Rounded down, so a key just short of a line never reads as standing on it.
     */
    public static function percent(int $used, int $ceiling): string
    {
        return sprintf('%.1f%%', floor($used / $ceiling * 1000) / 10);
    }

    /** A count grouped for reading, the way the ceilings in every message are written. */
    public static function grouped(int $value): string
    {
        return number_format($value, 0, '.', ',');
    }
}
