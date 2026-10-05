<?php

declare(strict_types=1);

namespace Pushery\SQLens\Config;

/**
 * The rule behind every timeout and limit `config/sqlens.php` reads from the environment.
 *
 * An environment value arrives as a string or null. A whole number of at least one is used as it
 * stands; anything else, an empty value, `0`, `-5` or a typo, gives the shipped default, so a
 * mistake in a deployment falls back to the value this package ships rather than to zero.
 */
final readonly class EnvironmentInteger
{
    /** The value as a whole number when it is one of at least one, the default otherwise. */
    public static function atLeastOne(mixed $value, int $default): int
    {
        return is_numeric($value) && (int) $value >= 1 ? (int) $value : $default;
    }
}
