<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

/**
 * What one comparison found, and what it could not look at.
 *
 * ## An empty entry list is not automatically good news
 *
 * `entries === []` means "compared and equal" only when `blindSpots === []` as well. Anything that
 * renders this must say both, and {@see isConclusive()} exists so a caller cannot get that wrong by
 * checking the obvious field alone.
 */
final readonly class DriftReport
{
    /**
     * @param  list<DriftEntry>  $entries  sorted by identity
     * @param  list<DriftBlindSpot>  $blindSpots  sorted by type and side
     */
    public function __construct(
        public array $entries = [],
        public array $blindSpots = [],
    ) {}

    /** Whether this run saw the whole schema — the question `entries` alone cannot answer. */
    public function isConclusive(): bool
    {
        return $this->blindSpots === [];
    }

    /**
     * The entries of one class, in the order the report carries them.
     *
     * @return list<DriftEntry>
     */
    public function of(DriftClass $class): array
    {
        return array_values(array_filter(
            $this->entries,
            static fn (DriftEntry $entry): bool => $entry->class === $class,
        ));
    }

    /**
     * Counts per class, every class present even at zero.
     *
     * Zeros included on purpose: a reader scanning for `missing_in_database` and finding the key
     * absent cannot tell "none" from "not measured", and that is the one distinction this package
     * refuses to blur.
     *
     * @return array<string, int>
     */
    public function counts(): array
    {
        $counts = [];

        foreach (DriftClass::cases() as $class) {
            $counts[$class->value] = count($this->of($class));
        }

        return $counts;
    }
}
