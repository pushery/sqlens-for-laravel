<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Catalog;

use RoundingMode;

/**
 * A PostgreSQL time setting as whole milliseconds, read the way the server reads the text.
 *
 * The text arrives in two places that keep the spelling they were given: a default stored with
 * `ALTER ROLE … SET` or `ALTER DATABASE … SET` (`10s`, `0.4ms`), and a `SET` in a migration.
 * `pg_settings` answers in the base unit, so comparing either with it takes the same reading.
 *
 * The server's grammar, which this follows: an integer may be written in hex (`0x10`) or octal
 * (`010`), a number that continues with a point or an exponent is read as a fraction, space may sit
 * between the number and the unit, and the unit is case-sensitive. A number without a unit is in
 * milliseconds, the unit `lock_timeout` and `statement_timeout` are kept in.
 *
 * A fraction of a millisecond is rounded to the nearest whole one, and a half to the even one, so
 * `0.5ms` and `100us` are `0`, which is no bound at all, while `0.6ms` is `1`. Measured on
 * PostgreSQL 18.4, one `SET lock_timeout` per value.
 */
final class DurationValue
{
    /** How many milliseconds one of each unit is. */
    private const array UNITS = ['us' => 0.001, 'ms' => 1, 's' => 1_000, 'min' => 60_000, 'h' => 3_600_000, 'd' => 86_400_000];

    private const string DURATION = '/^\s*(?<sign>[+-]?)(?:0[xX](?<hex>[0-9a-fA-F]+)|(?<octal>0[0-7]+)(?![0-9.eE])|(?<decimal>(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?))\s*(?<unit>us|ms|s|min|h|d)?\s*$/';

    /** The whole milliseconds the text stands for, or null when it is not a duration in this grammar. */
    public static function milliseconds(string $value): ?int
    {
        if (preg_match(self::DURATION, $value, $match) !== 1) {
            return null;
        }

        $number = match (true) {
            ($match['hex'] ?? '') !== '' => (float) hexdec($match['hex']),
            ($match['octal'] ?? '') !== '' => (float) octdec($match['octal']),
            default => (float) ($match['decimal'] ?? '0'),
        };

        $milliseconds = round($number * self::UNITS[($match['unit'] ?? '') === '' ? 'ms' : $match['unit']], 0, RoundingMode::HalfEven);

        return (int) ($match['sign'] === '-' ? -$milliseconds : $milliseconds);
    }
}
