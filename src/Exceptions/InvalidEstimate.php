<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use LogicException;
use Pushery\SQLens\Catalog\Statistics\EstimateSource;

/**
 * A statistics number was built in a shape it cannot have.
 *
 * A wiring error rather than a user error, so it throws instead of becoming an `undetermined`: an
 * undetermined says "we looked and could not tell", and both cases here are a reader that HAD the
 * answer and assembled it wrongly. Letting one through would put a number into a report that reads
 * like a measurement and is not one — and a report is exactly where that stops being visible.
 */
final class InvalidEstimate extends LogicException
{
    /**
     * A count or a size came through negative.
     *
     * Not a hypothetical. An engine that has never collected statistics for an object may answer
     * with a negative sentinel rather than with nothing, precisely so that "no statistics" cannot
     * pass for "no rows" — and a reader that forwards the sentinel undoes that on the engine's
     * behalf, ending with a report that says a table holds minus one row.
     *
     * The sentinel is resolved, not carried: it means the statistics were never collected, and the
     * count that goes with it is nothing at all rather than a number. A reading in that state is
     * reported as undetermined; no estimate is built.
     */
    public static function negativeValue(EstimateSource $source, int $value): self
    {
        return new self(sprintf(
            'A statistics value for %s came through as %d, and neither a count nor a size can be '
            .'negative. A negative value here is an engine sentinel meaning the object has never '
            .'been analyzed — read it as never-collected freshness with NO number, rather than '
            .'reporting an object with %d of them.',
            $source->value,
            $value,
            $value,
        ));
    }

    /**
     * An estimate was about to be dressed up as a measurement.
     *
     * The one mistake this whole type exists to prevent, and the reason it is stated about the
     * quantity rather than about a column: no catalog on any engine states a live-row count
     * exactly, because counting rows means counting rows — a full scan this package will never ask
     * a production database to perform. So a call site asking for one as exact is not making a
     * judgment that happens to be wrong; it is asking for something that does not exist.
     */
    public static function cannotBeExact(EstimateSource $source): self
    {
        return new self(sprintf(
            '%s is always an estimate and cannot be built as exact. No catalog read states it '
            .'exactly, so its number answers differently on the same schema depending on when '
            .'statistics were last refreshed — which is why it may never reach a rule. Build it with '
            .'measured(), neverCollected() or freshnessUnknown() and let the finding carry it as '
            .'context.',
            $source->value,
        ));
    }
}
