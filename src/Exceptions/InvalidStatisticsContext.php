<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use LogicException;
use Pushery\SQLens\Catalog\Statistics\EstimateSource;

/**
 * Statistics were attached to a finding in a shape that says nothing, or says the wrong thing.
 *
 * A wiring error rather than a user error, so it throws: both cases are a caller that had the
 * numbers and put them in the wrong place, and a finding is the last point at which anybody would
 * notice.
 */
final class InvalidStatisticsContext extends LogicException
{
    /**
     * A statistics context was built with no statistics in it.
     *
     * The failure it prevents is quiet: a reader that could establish nothing would attach an empty
     * context, the finding would carry a statistics section, and a reader of the report would take
     * the section's presence as evidence that somebody looked. A run that established nothing
     * attaches nothing, and the absence is then honest.
     */
    public static function carriesNothing(): self
    {
        return new self(
            'A statistics context was built with neither a count nor a size. A reading that '
            .'established nothing attaches nothing — an empty section on a finding reads as '
            .'"we looked and it was unremarkable", which is the opposite of what happened.',
        );
    }

    /** A count was passed where a size belongs, or the other way round. */
    public static function wrongUnit(string $slot, EstimateSource $source): self
    {
        return new self(sprintf(
            'The %s slot was given a %s statistic. The two travel through the same type and are '
            .'told apart by their unit, which is exactly why the slots check it: a size rendered as '
            .'a row count is off by a factor nobody can spot in a report.',
            $slot,
            $source->unit()->value,
        ));
    }
}
