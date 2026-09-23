<?php

declare(strict_types=1);

namespace Pushery\SQLens;

use Pushery\SQLens\Exceptions\InvalidRunDay;

/**
 * The calendar day one run judges on — created once, read everywhere.
 *
 * ## Why an object and not the `Y-m-d` string it wraps
 *
 * Because the property that has to be provable is IDENTITY, not equality. Two `gmdate('Y-m-d')`
 * calls in one run agree on almost every run and disagree across a midnight boundary, and a report
 * that says "2026-09-20" while its rules judged on the 21st is wrong in the one way nobody can spot
 * afterwards: both halves look plausible and neither says which clock it read.
 *
 * A string can only ever establish that two readers saw the same DAY, which is exactly the claim
 * that is true 99.9 % of the time and false when it matters. An object passed from one creation
 * point establishes that they read the same READING — `$a === $b` is an identity test, and it fails
 * the moment somebody adds a second source.
 *
 * ## The one clock, and the one place it is read
 *
 * {@see self::fromClock()} holds the only `gmdate('Y-m-d')` in the shipped tree outside the
 * documented fallback in `SecurityRuleSet::forProjectRoot()`. A run creates one of these at its
 * entry point and hands it on; nothing downstream asks the clock again.
 *
 * UTC, deliberately. The local reading follows the host app's `app.timezone`, so an application
 * east of UTC could have a support window closing on one calendar day and a debt acknowledgment
 * expiring on another, within one report, with nothing saying which side of midnight either was
 * on. Every timestamp this package compares against — a
 * tag, a pipeline, an advisory date — is already UTC, so UTC is the reading that needs no
 * conversion.
 *
 * ## Why {@see self::of()} exists and is not a test seam
 *
 * A run has to be reproducible on the day it mattered. Pinning the day is how a boundary judgment
 * gets re-examined at all, and it is the only way the arm that proves this mechanism can be written:
 * a test that could not pin the day would be asserting against the clock it runs under.
 */
final readonly class Today
{
    private function __construct(
        /** The day, as `Y-m-d` — the form every consumer of a report already reads. */
        public string $value,
    ) {}

    /**
     * Read the clock. The one call site, once per run.
     *
     * Not memoized: a memoized reading is a value that outlives the run that made it, which is the
     * container-singleton defect this class replaces rather than a cheaper version of it.
     */
    public static function fromClock(): self
    {
        return new self(gmdate('Y-m-d'));
    }

    /**
     * A pinned day, for a reproduced run.
     *
     * Validated rather than trusted, and the validation is narrow on purpose: the format is the
     * contract, so `2026-9-1` is refused even though `strtotime` would happily read it. A report
     * whose header carries a day in a second format is a report two consumers parse differently.
     */
    public static function of(string $day): self
    {
        if (preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', $day, $parts) !== 1) {
            throw InvalidRunDay::malformed($day);
        }

        // The format check is not the date check, and only the second one catches `2026-02-30`.
        // A regex accepts any two digits, so a month of 13 or a February 30th passes it and then
        // prints into a header as a day nothing happened on.
        if (! checkdate((int) $parts[2], (int) $parts[3], (int) $parts[1])) {
            throw InvalidRunDay::notACalendarDay($day);
        }

        return new self($day);
    }
}
