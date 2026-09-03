<?php

declare(strict_types=1);

namespace Pushery\SQLens\Findings;

use Pushery\SQLens\Catalog\Statistics\Estimate;
use Pushery\SQLens\Catalog\Statistics\EstimateUnit;
use Pushery\SQLens\Exceptions\InvalidStatisticsContext;

/**
 * Optional statistics context on a finding — how big the object is, as far as anybody can tell.
 *
 * It is CONTEXT, never a fourth subject and never the basis of a status decision: statistics
 * escalate severity, they never create a rule class. A rule that read a row count would answer
 * differently on the same schema depending on when statistics were last refreshed, and would have
 * no way to say so.
 *
 * Both slots carry {@see Estimate} rather than a bare integer, and that replaced a scaffold that
 * carried `int` with an `isEstimate()` that returned a hard-coded `true`. The hard-coded answer was
 * a convention wearing a method's clothes, and it was already wrong in one direction: a size some
 * engines compute while answering is a measurement, not an estimate, and calling it one invites a
 * reader to distrust the one number they need not. Each number now says for itself what it is worth
 * and how old the statistics behind it are.
 */
final readonly class StatisticsContext
{
    private function __construct(
        /** How many rows the object is believed to hold, or null when the reading established none. */
        public ?Estimate $rows,
        /** How many bytes it occupies, or null when the reading established none. */
        public ?Estimate $bytes,
    ) {}

    /**
     * A context carrying whatever the reading could establish — at least one of the two.
     *
     * The units are checked rather than trusted. Rows and bytes travel through the same type, so
     * passing them in the wrong order is a mistake the type system cannot catch on its own, and a
     * size rendered as a row count is off by a factor nobody spots in a report.
     */
    public static function of(?Estimate $rows = null, ?Estimate $bytes = null): self
    {
        if (! $rows instanceof Estimate && ! $bytes instanceof Estimate) {
            throw InvalidStatisticsContext::carriesNothing();
        }

        if ($rows instanceof Estimate && $rows->unit() !== EstimateUnit::Rows) {
            throw InvalidStatisticsContext::wrongUnit('row', $rows->source);
        }

        if ($bytes instanceof Estimate && $bytes->unit() !== EstimateUnit::Bytes) {
            throw InvalidStatisticsContext::wrongUnit('size', $bytes->source);
        }

        return new self($rows, $bytes);
    }

    /**
     * Whether every number here was measured rather than remembered.
     *
     * Replaces the scaffold's `isEstimate()`, which answered `true` for everything and so answered
     * nothing. A context can now be mixed — an exact size beside an estimated row count is the
     * ordinary case on one engine — so the honest question is whether ALL of it is exact, and the
     * answer for a mixed context is `false`.
     */
    public function isFullyExact(): bool
    {
        return array_all($this->estimates(), fn (Estimate $estimate): bool => $estimate->isExact());
    }

    /**
     * Whether any number here rests on statistics that were never collected.
     *
     * Three-valued, and the third answer is the one worth having: `null` means at least one
     * freshness could not be read and none of the others was stale, so the context cannot be
     * certified either way. Answering `false` there would report statistics nobody looked at as
     * sound.
     */
    public function isStale(): ?bool
    {
        $undetermined = false;

        foreach ($this->estimates() as $estimate) {
            $stale = $estimate->isStale();

            if ($stale === true) {
                return true;
            }

            if ($stale === null) {
                $undetermined = true;
            }
        }

        return $undetermined ? null : false;
    }

    /** A stable rendering of everything present, so two readings diff cleanly. */
    public function describe(): string
    {
        return implode(', ', array_map(
            static fn (Estimate $estimate): string => $estimate->describe(),
            $this->estimates(),
        ));
    }

    /**
     * The JSON projection, with the two DERIVED answers beside the numbers.
     *
     * `is_estimate` and `is_stale` are computed here rather than left to a consumer, and that is
     * the whole point of the field: a machine reading `rows: 4200` has no way to know that the
     * number is a guess, and every downstream decision about severity depends on it. Shipping the
     * estimates without the flags would be shipping the same trap this type exists to close.
     *
     * `is_stale` keeps three values — `null` means at least one freshness could not be read, and
     * `false` would report statistics nobody looked at as sound.
     *
     * @return array{rows?: array<string, mixed>, bytes?: array<string, mixed>, is_estimate: bool, is_stale: bool|null}
     */
    public function toArray(): array
    {
        $projection = [
            'rows' => $this->rows?->toArray(),
            'bytes' => $this->bytes?->toArray(),
        ];

        return [
            ...array_filter($projection, static fn (?array $value): bool => $value !== null),
            'is_estimate' => ! $this->isFullyExact(),
            'is_stale' => $this->isStale(),
        ];
    }

    /**
     * Whichever slots are filled, rows first.
     *
     * Public because a REPORTER has to narrate each number separately: the marker belongs to the
     * value, and a context rendered as one string could only carry one marker for a reading whose
     * halves genuinely differ — an estimated row count beside an exact size is the ordinary case on
     * PostgreSQL.
     *
     * @return list<Estimate>
     */
    public function estimates(): array
    {
        return array_values(array_filter(
            [$this->rows, $this->bytes],
            static fn (?Estimate $estimate): bool => $estimate instanceof Estimate,
        ));
    }
}
