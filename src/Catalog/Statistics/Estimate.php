<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Statistics;

use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;
use Pushery\SQLens\Exceptions\InvalidEstimate;

/**
 * One statistics number with everything needed to know what it is worth — the value, what it is a
 * statistic of, how precise that makes it, and what is known about the age of the statistics behind
 * it.
 *
 * The master plan's ninth pitfall is not that an estimated row count is wrong. It is that
 * `480000000` looks exactly like a count, so the distinction survives only as long as every hand it
 * passes through remembers a convention — and conventions are load-bearing right up until the day
 * somebody writes `if ($rows > 1_000_000)` in a rule, which is the day the tool starts answering
 * differently on an unchanged schema depending on when statistics were last refreshed, with no way
 * to say so.
 *
 * So the marking is a type, and three properties make remembering unnecessary:
 *
 *   - **The number cannot be had without knowing what it counts.** The constructor is private and
 *     every factory requires an {@see EstimateSource}.
 *   - **Precision is never an independent field.** It follows from the freshness, which follows
 *     from which factory was called, so there is no second value that can disagree with the first.
 *     A row count additionally cannot take the exact road at all — no catalog read states one.
 *   - **It cannot reach a rule.** Rules take subjects, and this is not one: statistics attach to a
 *     FINDING as context, which the subject-set guard holds closed at three.
 *
 * **This type never reads the clock.** Age is carried as the server's own timestamp for the last
 * statistics refresh, never as a distance from now, and the comparison in {@see self::isOlderThan()}
 * takes its reference as an argument. That is the determinism principle applied where it is easiest
 * to lose: a value object that asked the current time what it thought would render one string this
 * second and a different one the next, and two runs over an unchanged database would diff. A guard
 * beside this class holds it at the source.
 */
final readonly class Estimate
{
    /**
     * Private, so the four factories below are the only way in.
     *
     * That is what makes the pairing of {@see self::$freshness} and {@see self::$measuredAt} an
     * invariant rather than an agreement: `Measured` carries a timestamp and the other three carry
     * none, and no call site can assemble a fifth combination to disagree about.
     */
    private function __construct(
        /** The count or the size. Never negative — {@see InvalidEstimate::negativeValue()}. */
        public int $value,
        public EstimateSource $source,
        public EstimateFreshness $freshness,
        /**
         * When the statistics behind this number were last refreshed, as the SERVER reports it.
         *
         * Non-null exactly when the freshness is `Measured`. It is the server's timestamp and not
         * ours on purpose: a reading that stamped its own clock would be recording when SQLens
         * looked, which is a fact about the audit rather than about the database, and the two
         * differ by however far the two clocks have drifted.
         */
        public ?DateTimeImmutable $measuredAt,
    ) {}

    /**
     * A number the server computed while answering — exact at the moment of the read.
     *
     * The road a driver takes for a quantity its engine measures rather than remembers, and the
     * road a row count can never take: {@see EstimateSource::isAlwaysEstimated()} closes it, which
     * is the single refusal this type exists for.
     */
    public static function exact(int $value, EstimateSource $source): self
    {
        if ($source->isAlwaysEstimated()) {
            throw InvalidEstimate::cannotBeExact($source);
        }

        return new self(self::nonNegative($value, $source), $source, EstimateFreshness::NotApplicable, null);
    }

    /** An estimate whose statistics the server last refreshed at a known moment. */
    public static function measured(int $value, EstimateSource $source, DateTimeImmutable $measuredAt): self
    {
        return new self(self::nonNegative($value, $source), $source, EstimateFreshness::Measured, $measuredAt);
    }

    /**
     * An estimate the server states has never had statistics collected for it.
     *
     * The value stays readable, and that is the point of having the case at all: an engine with no
     * persistent statistics for a table can still answer with a number sampled on the spot, so
     * refusing to carry it would discard something usable in order to record that it is weak. It is
     * carried, and marked.
     *
     * Where the engine answers with a SENTINEL instead of a number — PostgreSQL writes -1 into its
     * row estimate for a relation nobody has analyzed — there is nothing to carry, and the reader
     * reports the statistic as undetermined rather than building anything here. The negative check
     * below is what makes that a rule rather than a habit.
     */
    public static function neverCollected(int $value, EstimateSource $source): self
    {
        return new self(self::nonNegative($value, $source), $source, EstimateFreshness::NeverCollected, null);
    }

    /**
     * An estimate whose age could not be established — a withheld view, a missing privilege, an
     * engine that does not report it.
     *
     * Not the same as never collected, and kept apart from it for the reason the whole package is
     * built on: one of them is fixed by refreshing the statistics and the other cannot be fixed by
     * running anything.
     */
    public static function freshnessUnknown(int $value, EstimateSource $source): self
    {
        return new self(self::nonNegative($value, $source), $source, EstimateFreshness::Unknown, null);
    }

    /**
     * How much this number is worth.
     *
     * Derived from the freshness rather than stored beside it, which is what keeps the two from
     * ever disagreeing: exactly one factory produces a number with no statistics behind it, and
     * that is exactly the number that was measured while the server answered.
     */
    public function precision(): EstimatePrecision
    {
        return $this->freshness === EstimateFreshness::NotApplicable
            ? EstimatePrecision::ExactAtReadTime
            : EstimatePrecision::Estimated;
    }

    /** What it counts — rows or bytes. */
    public function unit(): EstimateUnit
    {
        return $this->source->unit();
    }

    /** Whether the server measured this while answering, rather than remembering it. */
    public function isExact(): bool
    {
        return $this->precision()->isExact();
    }

    /**
     * Whether this number rests on statistics that were never collected.
     *
     * Deliberately NOT "is it old". Age needs a reference point, and a value object that supplied
     * one from the wall clock would answer differently every time it was asked — see
     * {@see self::isOlderThan()}, which takes its reference as an argument. `Measured` therefore
     * answers `false` however long ago that moment was: what is reported here is whether there are
     * statistics behind the number at all.
     *
     * Three-valued, because the third answer is a real state: `Unknown` means the freshness could
     * not be read, and answering `false` there would certify statistics nobody looked at.
     */
    public function isStale(): ?bool
    {
        return match ($this->freshness) {
            EstimateFreshness::NeverCollected => true,
            EstimateFreshness::Measured, EstimateFreshness::NotApplicable => false,
            EstimateFreshness::Unknown => null,
        };
    }

    /**
     * Whether the statistics behind this number predate a moment the CALLER names.
     *
     * The reference is a parameter and never `now`, which is what keeps this deterministic: the
     * same estimate compared against the same reference answers the same on a dev machine in August
     * and in CI in November. A caller who genuinely wants "older than an hour ago" computes that
     * moment itself, and owns the fact that its answer moves.
     *
     * `NeverCollected` answers `true` against any reference — there is no statistic from after the
     * reference, because there is none at all. `NotApplicable` answers `false`: a number measured
     * while the server answered has nothing behind it that could predate anything. `Unknown`
     * answers null, because a timestamp nobody could read is not evidence in either direction.
     */
    public function isOlderThan(DateTimeImmutable $reference): ?bool
    {
        $measuredAt = $this->measuredAt;

        return match ($this->freshness) {
            EstimateFreshness::Measured => $measuredAt instanceof DateTimeImmutable && $measuredAt < $reference,
            EstimateFreshness::NeverCollected => true,
            EstimateFreshness::NotApplicable => false,
            EstimateFreshness::Unknown => null,
        };
    }

    /**
     * A stable rendering, so two readings of an unchanged database diff cleanly.
     *
     * Every part of it is deterministic on purpose. The number is written plainly rather than
     * grouped, because thousands separators are locale-dependent and a report that renders
     * `1,000,000` on one machine and `1.000.000` on another diffs on nothing. The timestamp is
     * normalized to UTC in a fixed format for the same reason: the same moment read through two
     * session timezones is one moment, and it must produce one string.
     */
    public function describe(): string
    {
        $measuredAt = $this->measuredAt;

        return sprintf(
            '%d %s (%s, %s, %s)',
            $this->value,
            $this->unit()->value,
            $this->isExact() ? 'exact at read time' : 'estimated',
            $this->source->value,
            match ($this->freshness) {
                EstimateFreshness::Measured => $measuredAt instanceof DateTimeImmutable
                    ? 'statistics from '.$measuredAt->setTimezone(new DateTimeZone('UTC'))->format(DateTimeInterface::ATOM)
                    : 'statistics age unknown',
                EstimateFreshness::NeverCollected => 'statistics never collected',
                EstimateFreshness::Unknown => 'statistics age unknown',
                EstimateFreshness::NotApplicable => 'no statistics behind it',
            },
        );
    }

    /**
     * The serializable form — every fact this number carries, none of it recomputable from the rest.
     *
     * The precision and the unit are written out even though both are derived, because this array
     * is read by things that are not PHP: a JSON report, a golden file, a diff between two runs. A
     * consumer over there cannot call a method, and a number that arrived without its precision is
     * exactly the bare integer this type exists to prevent.
     *
     * The timestamp is normalized to UTC in a fixed format, so the same moment read through two
     * session timezones serializes to one string and two runs over an unchanged database do not
     * diff on how it was spelled.
     *
     * @return array{value: int, source: string, unit: string, precision: string, freshness: string, measured_at: string|null}
     */
    public function toArray(): array
    {
        return [
            'value' => $this->value,
            'source' => $this->source->value,
            'unit' => $this->unit()->value,
            'precision' => $this->precision()->value,
            'freshness' => $this->freshness->value,
            'measured_at' => $this->measuredAt?->setTimezone(new DateTimeZone('UTC'))->format(DateTimeInterface::ATOM),
        ];
    }

    /** @throws InvalidEstimate when an engine's never-collected sentinel was forwarded as a value */
    private static function nonNegative(int $value, EstimateSource $source): int
    {
        if ($value < 0) {
            throw InvalidEstimate::negativeValue($source, $value);
        }

        return $value;
    }
}
