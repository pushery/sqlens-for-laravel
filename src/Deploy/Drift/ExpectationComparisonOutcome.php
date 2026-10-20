<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

use Pushery\SQLens\Catalog\CatalogContext;

/**
 * What one expectation comparison produced — a report, or a named reason there is none.
 *
 * Two states rather than a nullable report, for the reason the whole deploy layer is built on: "the
 * schemas match" and "no expectation could be built" are different answers, and a caller handed a
 * null would have to remember which one it meant. Here the reason travels with the absence.
 *
 * There is deliberately NO `isComplete()` helper, and its absence is load-bearing rather than an
 * omission. Both callers narrow with `$outcome->report instanceof DriftReport`, because a method
 * call cannot narrow a nullable in PHPStan: with a helper the report would stay `?DriftReport`
 * inside the very branch that exists because there is one, and every use of it would take a null
 * the type system had already been told could not arrive. The helper was written, shipped unused,
 * and removed — reading the property keeps the invariant in the types.
 */
final readonly class ExpectationComparisonOutcome
{
    /**
     * @param  CatalogContext|null  $live  what the live reading said about the server it read, the
     *                                     version a report names among it; null when the comparison
     *                                     never read the live database
     */
    private function __construct(
        public ?DriftReport $report,
        public ?ShadowReferenceOutcome $reference,
        public ?CatalogContext $live = null,
    ) {}

    public static function compared(DriftReport $report, ShadowReferenceOutcome $reference, ?CatalogContext $live = null): self
    {
        return new self($report, $reference, $live);
    }

    public static function unavailable(ShadowReferenceOutcome $reference): self
    {
        return new self(null, $reference);
    }
}
