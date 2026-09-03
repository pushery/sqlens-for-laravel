<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use InvalidArgumentException;
use Pushery\SQLens\Categories\Category;

/**
 * A `--category` (or `sqlens.categories`) value was given that names no known
 * category — a user misconfiguration, never a silently dropped filter token. A
 * quietly ignored typo would let a run filter to nothing and read as "clean", the
 * exact false green this package refuses. The message lists every valid category so
 * the fix is obvious. Maps to the misconfiguration exit status.
 */
final class UnknownCategory extends InvalidArgumentException
{
    private function __construct(public readonly string $requested, string $message)
    {
        parent::__construct($message);
    }

    public static function named(string $requested): self
    {
        return new self($requested, sprintf(
            'Unknown category "%s". Available categories: %s.',
            $requested,
            implode(', ', self::available()),
        ));
    }

    /**
     * The valid category values, for a localized message that lists them.
     *
     * @return list<string>
     */
    public static function available(): array
    {
        return array_map(static fn (Category $category): string => $category->value, Category::cases());
    }
}
