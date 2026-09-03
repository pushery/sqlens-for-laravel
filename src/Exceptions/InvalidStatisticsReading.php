<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use LogicException;
use Pushery\SQLens\Catalog\Statistics\EstimateSource;

/**
 * A statistics reading was assembled in a shape that would misreport what it measured.
 *
 * Wiring errors rather than user errors, so they throw: in every case the reader HAD the numbers
 * and put them somewhere they mean something else. A statistics reading is consumed to weight a
 * finding's severity, and a size that arrived in the row slot would weight it by a factor of eight
 * thousand without anything looking wrong.
 */
final class InvalidStatisticsReading extends LogicException
{
    /** A number arrived in a slot that measures something else. */
    public static function wrongQuantity(string $slot, EstimateSource $expected, EstimateSource $given): self
    {
        return new self(sprintf(
            'The %s slot was given a %s statistic where a %s one belongs. The slots check this '
            .'rather than trusting it: every number here is the same type, so the compiler cannot '
            .'tell them apart, and a size weighted as a row count is wrong by a factor nobody spots '
            .'in a report.',
            $slot,
            $given->value,
            $expected->value,
        ));
    }
}

// There is deliberately no "degraded headroom carries no reason" factory here, and its absence is
// the better outcome rather than an oversight. That rule wanted enforcing — free space is commonly
// unreadable through SQL, so the degraded reading is the NORMAL one, and a normal state with no
// reason attached is the state a consumer learns to read as "fine". It is enforced STRUCTURALLY
// instead: `StorageHeadroom`'s constructor is private and each degraded factory takes the
// `CatalogSkip` as a required argument, so the invalid shape has no construction path and needs no
// exception to describe it. A throw that can never fire is a rule nobody is holding.
