<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Squawk;

/**
 * What SQLens itself does about the ground a tool rule covers.
 *
 * An honesty instrument, not a marketing one. Its job is to make "we do not check this"
 * visible — including where the decision not to check was deliberate, which is the entry a
 * comparison table would quietly leave out.
 */
enum SquawkParityStatus: string
{
    /** SQLens has a rule that reaches the same verdict on the same statement. */
    case Covered = 'covered';

    /**
     * SQLens covers the same ground from a different angle.
     *
     * Kept apart from {@see self::Covered} because de-duplication reads it: two findings about
     * the same statement may still be two different pieces of advice, and dropping one of them
     * would drop the fix the reader needed.
     */
    case CoveredDifferently = 'covered_differently';

    /**
     * SQLens has no rule and wants none — a decision, with the reasoning in the entry.
     *
     * The tool's finding is not surfaced under this status: it is the one status that says the
     * question was asked and answered no.
     */
    case IntentionallyNotCovered = 'intentionally_not_covered';

    /** No SQLens rule exists; the tool's finding is surfaced under the tool's own identifier. */
    case MappedOnly = 'mapped_only';

    /** Whether a finding under this status reaches the report at all. */
    public function surfaces(): bool
    {
        return $this !== self::IntentionallyNotCovered;
    }

    /** @return list<string> */
    public static function names(): array
    {
        return array_map(static fn (self $case): string => $case->value, self::cases());
    }
}
