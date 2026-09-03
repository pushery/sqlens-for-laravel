<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Severity\Severity;

/**
 * How long a debt has been outstanding, as a named band rather than a raw number.
 *
 * The bands exist because a number alone does not tell anybody what to do. "Open since 94 days" is
 * information; "open since 94 days, past the warning threshold this project set" is a decision the
 * project already made, applied. The thresholds are configurable and the bands are not: a project
 * chooses WHEN a debt gets louder, never invents a new loudness.
 */
enum DebtTier: string
{
    /** Old enough to mention. Nothing is wrong; somebody should know it is still there. */
    case Notice = 'notice';

    /** Old enough that it has stopped being a plan and started being a habit. */
    case Warning = 'warning';

    /** Old enough that the safe half of a safe pattern is not coming. */
    case Error = 'error';

    /**
     * The severity a debt in this band is worth AT LEAST.
     *
     * `Error` maps to {@see Severity::High} and deliberately not to `Critical`. Critical is the top
     * of the SECURITY severity axis — an exposed credential, an open policy — and an unvalidated
     * constraint is a safety debt however old it is. A band that reached Critical would make the
     * oldest maintenance debt outrank every real security finding in the same report, and the axis
     * would stop meaning what its own gate says it means.
     */
    public function severity(): Severity
    {
        return match ($this) {
            self::Notice => Severity::Low,
            self::Warning => Severity::Medium,
            self::Error => Severity::High,
        };
    }

    /**
     * The bands from the oldest down, so the first match is the loudest one that applies.
     *
     * @return list<self>
     */
    public static function loudestFirst(): array
    {
        return [self::Error, self::Warning, self::Notice];
    }
}
