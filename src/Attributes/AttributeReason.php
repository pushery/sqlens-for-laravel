<?php

declare(strict_types=1);

namespace Pushery\SQLens\Attributes;

/**
 * Whether the reason an attribute carries says anything.
 *
 * Every attribute this package reads takes a reason, and PHP can make the argument required but not
 * meaningful: `reason: ''` and `reason: ' '` satisfy the signature and state nothing. Nor does PHP
 * look at the arguments when the file loads. It checks them when the attribute is instantiated, and
 * the pre-scan and the analyse suite never instantiate one, they read it from the source. So the
 * reason is checked where the package reads the attribute, by this one rule for every attribute,
 * and an attribute whose reason states nothing counts as absent: the finding it was written for is
 * reported.
 */
final readonly class AttributeReason
{
    /** Whether the reason states anything: it is neither empty nor only whitespace. */
    public static function states(string $reason): bool
    {
        return trim($reason) !== '';
    }
}
