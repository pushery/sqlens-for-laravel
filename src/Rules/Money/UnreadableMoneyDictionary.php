<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Money;

use RuntimeException;

/**
 * The money-column dictionary could not be read, or is not the shape this build implements.
 *
 * Thrown rather than degraded to an empty list, and the direction is the point: an empty dictionary
 * makes the rule silent while every test about the rule still passes. A heuristic that quietly stops
 * finding anything is indistinguishable from a codebase that has nothing to find.
 */
final class UnreadableMoneyDictionary extends RuntimeException
{
    public function __construct(string $path, string $why)
    {
        parent::__construct(sprintf(
            'The money-column dictionary at %s cannot be used: %s. It is refused rather than treated as '
            .'empty — an empty dictionary would make the rule silent while looking healthy.',
            $path,
            $why,
        ));
    }
}
