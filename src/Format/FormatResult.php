<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

/**
 * What one formatting attempt produced: formatted SQL, or a named reason there is none.
 *
 * ## Two states and never an exception
 *
 * No formatter in this package throws outward. A missing binary, a timeout, an unparsable statement
 * and an option a backend cannot express are all ORDINARY — they happen on real machines, in CI
 * containers, on the day somebody upgrades a tool — and a suite that formatted a hundred files must
 * report the two it could not rather than dying on the third.
 *
 * ## Why the mode, the version and the fingerprint ride along
 *
 * Formatted output is only reproducible if what produced it is known. Three runs can disagree for
 * three unrelated reasons — a different backend, a different tool version, a different style — and a
 * result that carried none of them would leave a team diffing output to work out which. Every one
 * of the three is in the result, so the report can simply say.
 */
final readonly class FormatResult
{
    private function __construct(
        public ?string $sql,
        public string $formatter,
        public Dialect $dialect,
        public string $styleFingerprint,
        public ?string $toolVersion,
        public ?FormatUndeterminedReason $reason,
        public ?string $detail,
    ) {}

    public static function formatted(
        string $sql,
        string $formatter,
        Dialect $dialect,
        FormatStyle $style,
        ?string $toolVersion = null,
    ): self {
        return new self($sql, $formatter, $dialect, $style->fingerprint(), $toolVersion, null, null);
    }

    /**
     * No output, and the reason is a REQUIRED argument.
     *
     * Unconstructible without one, the same shape `FindingStatus::undetermined()` uses: an anonymous
     * undetermined is exactly what a rushed `catch` produces, and it is indistinguishable in a report
     * from a formatter that had nothing to do.
     *
     * @param  string|null  $detail  what the tool said, passed through rather than interpreted
     */
    public static function undetermined(
        FormatUndeterminedReason $reason,
        string $formatter,
        Dialect $dialect,
        FormatStyle $style,
        ?string $detail = null,
        ?string $toolVersion = null,
    ): self {
        return new self(null, $formatter, $dialect, $style->fingerprint(), $toolVersion, $reason, $detail);
    }

    /**
     * Whether this attempt produced SQL.
     *
     * Narrow on `$result->sql !== null` where the value is then USED — a method call cannot narrow a
     * nullable, so a caller that asked this question and then read `->sql` would still be handed a
     * `?string`. This exists for the places that only need to count.
     */
    public function isFormatted(): bool
    {
        return $this->sql !== null;
    }
}
