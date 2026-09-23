<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use InvalidArgumentException;

/**
 * A pinned run day is not a day.
 *
 * This is a user misconfiguration and not a packaging error, which is why it extends
 * `InvalidArgumentException` rather than the `LogicException` the bundled-artifact exceptions use: a
 * pinned day arrives from a caller — a reproduced run, a boundary judgment being re-examined — and
 * the honest answer to a bad one is to refuse it by name.
 *
 * Refusing rather than falling back to the clock is the whole point. A silent fallback would answer
 * a question about one day with a reading of another, and the header would then name a day the run
 * was never asked about — the exact confusion the run clock exists to remove.
 */
final class InvalidRunDay extends InvalidArgumentException
{
    /** Not in the `Y-m-d` shape a report header promises. */
    public static function malformed(string $day): self
    {
        return new self(sprintf(
            'A pinned run day must be written as Y-m-d, four digits, two, two — "%s" is not. '
            .'The format is the contract: a header carrying a second format is a header two '
            .'consumers parse differently.',
            $day,
        ));
    }

    /** The right shape, and no such day in the calendar. */
    public static function notACalendarDay(string $day): self
    {
        return new self(sprintf(
            'The pinned run day "%s" has the right shape and is not a day that exists. A month '
            .'past 12 or a February 30th passes a format check and then prints into a report '
            .'header as a day on which nothing happened.',
            $day,
        ));
    }
}
