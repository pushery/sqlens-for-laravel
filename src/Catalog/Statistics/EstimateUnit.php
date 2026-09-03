<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Statistics;

/**
 * What a statistics number counts.
 *
 * A bare integer with an implicit unit is the same class of defect as a bare integer with an
 * implicit provenance: both work for exactly as long as every reader happens to remember the
 * convention. Rows and bytes travel through the same field on the same object here, so the one
 * arithmetic mistake worth designing against — adding a row count to a byte count, or rendering one
 * as the other — is prevented by the unit being carried rather than assumed.
 *
 * Derived from {@see EstimateSource} and never passed in: a source knows what it counts, and a call
 * site re-stating it can only ever restate it wrongly.
 */
enum EstimateUnit: string
{
    case Rows = 'rows';
    case Bytes = 'bytes';
}
