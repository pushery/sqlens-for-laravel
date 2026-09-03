<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use InvalidArgumentException;

/**
 * A report format was requested that no reporter answers to — a user
 * misconfiguration (a typo in `--format` or `sqlens.reporting.default_format`),
 * never a silent fallback to console. The message names every available format so
 * the fix is obvious. This maps to the misconfiguration exit status, not a clean
 * or a findings result.
 */
final class UnknownReporterFormat extends InvalidArgumentException
{
    /**
     * @param  list<string>  $available
     */
    private function __construct(public readonly string $requested, public readonly array $available, string $message)
    {
        parent::__construct($message);
    }

    /**
     * @param  list<string>  $available
     */
    public static function format(string $requested, array $available): self
    {
        return new self($requested, $available, sprintf(
            'Unknown report format "%s". Available formats: %s.',
            $requested,
            implode(', ', $available),
        ));
    }
}
