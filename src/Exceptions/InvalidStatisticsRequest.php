<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use InvalidArgumentException;

/**
 * A statistics reading was asked for in a way that would make it read too much, or nothing.
 *
 * Both refusals are about the same property. A statistics reading is not a survey of the instance:
 * it exists to weight findings that already exist, so it reads the objects those findings name and
 * no others. A request that failed to say which objects it meant would either scan an entire
 * production database at the one moment nobody wants extra load on it, or scan nothing while
 * looking exactly like a reading that found nothing remarkable.
 */
final class InvalidStatisticsRequest extends InvalidArgumentException
{
    /**
     * The request named no objects.
     *
     * Deliberately NOT read as "then read everything". That reading is what turns a targeted lookup
     * into a full catalog sweep, and it would arrive silently: the caller that forgot to pass its
     * object list gets a bigger answer than it asked for rather than an error, and the cost lands on
     * somebody's production instance minutes before a deploy.
     *
     * A caller that genuinely has nothing to look up does not build a request.
     */
    public static function namesNoObjects(): self
    {
        return new self(
            'A statistics request must name the objects it wants statistics for. An empty list is '
            .'not read as "everything": this reading exists to weight findings that already exist, '
            .'so it reads what those findings reference and nothing else. A caller with nothing to '
            .'look up builds no request.',
        );
    }

    /** An object reference came through empty, so the reading would look up nothing under a name. */
    public static function namesAnEmptyObject(): self
    {
        return new self(
            'A statistics request carries an empty object reference. A blank name reads as an object '
            .'that was looked up and found unremarkable, which is the one thing it is not.',
        );
    }

    /**
     * The time budget was zero or negative.
     *
     * The share exists so a statistics reading cannot spend the whole run's budget; a share of zero
     * does not express restraint, it expresses a reading that cannot happen, and a reader handed one
     * would report every object as skipped for a reason that is really a caller's arithmetic error.
     */
    public static function hasNoTimeBudget(int $milliseconds): self
    {
        return new self(sprintf(
            'A statistics request was given a time budget of %d ms. A reading needs a positive share '
            .'of the run\'s budget; zero is not restraint, it is a reading that cannot happen and '
            .'would report every object as skipped.',
            $milliseconds,
        ));
    }
}
