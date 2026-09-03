<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use InvalidArgumentException;

/**
 * A live-activity reading was asked for in a way that would make it report nothing usable.
 *
 * Each refusal is about the same failure: a reading that returns an empty list is indistinguishable
 * from a quiet server, and "quiet" is the answer a deploy gate acts on by proceeding.
 */
final class InvalidActivityRequest extends InvalidArgumentException
{
    /**
     * The long-running threshold was zero or negative.
     *
     * Zero does not mean "report everything" — it means every session on the server qualifies,
     * including the reading's own, and a preflight that listed hundreds of rows is one nobody reads
     * a second time. A caller who genuinely wants a very low bar states a low number.
     */
    public static function hasNoThreshold(int $milliseconds): self
    {
        return new self(sprintf(
            'A long-running threshold of %d ms would qualify every session on the server, including '
            .'this reading\'s own. State the shortest duration actually worth reporting; a preflight '
            .'nobody reads twice is one that stops being read at all.',
            $milliseconds,
        ));
    }

    /** The time budget was zero or negative — a reading that cannot happen, not restraint. */
    public static function hasNoTimeBudget(int $milliseconds): self
    {
        return new self(sprintf(
            'An activity request was given a time budget of %d ms. A reading needs a positive share '
            .'of the run\'s budget; zero would report every source as skipped for a reason that is '
            .'really a caller\'s arithmetic.',
            $milliseconds,
        ));
    }

    /** A focus relation came through blank, so it could never match anything the reading found. */
    public static function namesAnEmptyObject(): self
    {
        return new self(
            'An activity request carries an empty relation name. It would match nothing the reading '
            .'reports, so the deploy\'s own tables would silently lose their emphasis.',
        );
    }
}
