<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Statistics;

use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Exceptions\InvalidStatisticsReading;

/**
 * How much room a database or tablespace occupies, and how much is left — where either is knowable.
 *
 * The capacity picture behind the question a deploy gate most wants to ask and most often cannot:
 * will the rewrite this migration triggers fit. A table rewrite needs room for a second copy, an
 * index build needs room for the index plus its sort, and both need whatever the write-ahead log
 * grows to in the meantime. None of that is answerable without knowing what is left.
 *
 * ## Degraded readings must carry their reason, and the type enforces it
 *
 * Through SQL alone, at least one major engine will report how much space a database occupies and
 * will not report how much room is left on the volume underneath it. So the degraded reading is the
 * NORMAL one — which is exactly why it may not be a blank space. A consumer that met a missing
 * free-space number often enough with no explanation attached would learn to read it as "fine", and
 * the one time it meant "the role may not look" would read the same.
 *
 * Each degraded factory therefore takes a {@see CatalogSkip}, which already refuses to exist
 * without a named reason. The snapshot folds those skips into its own list, so a partially readable
 * headroom makes the whole reading visibly partial rather than quietly so.
 */
final readonly class StorageHeadroom
{
    /**
     * Private, so the three factories are the only way in.
     *
     * That is what makes "degraded implies a reason" an invariant rather than an agreement: there
     * is no constructor call that can assemble a missing number without the skip that explains it.
     */
    private function __construct(
        /** The database or tablespace this describes, as the reading names it. */
        public string $reference,
        /** Bytes currently occupied, or null when even that could not be read. */
        public ?Estimate $usedBytes,
        /** Bytes still available, or null when the engine will not say — the ordinary case. */
        public ?Estimate $freeBytes,
        /**
         * The skips that explain whatever is missing here — empty only for a complete reading.
         *
         * @var list<CatalogSkip>
         */
        public array $skips,
    ) {}

    /** Both numbers arrived. The only state in which a capacity question can be answered. */
    public static function complete(string $reference, Estimate $usedBytes, Estimate $freeBytes): self
    {
        self::mustMeasure('storage used', $usedBytes, EstimateSource::StorageUsedBytes);
        self::mustMeasure('storage free', $freeBytes, EstimateSource::StorageFreeBytes);

        return new self($reference, $usedBytes, $freeBytes, []);
    }

    /**
     * The size is known and the free space is not, with the skip that says why not.
     *
     * The common shape, and the reason the skip is a required argument rather than an optional one.
     */
    public static function sizeOnly(string $reference, Estimate $usedBytes, CatalogSkip $freeSpaceSkip): self
    {
        self::mustMeasure('storage used', $usedBytes, EstimateSource::StorageUsedBytes);

        return new self($reference, $usedBytes, null, [$freeSpaceSkip]);
    }

    /** Neither number arrived, with the skip that says why. */
    public static function unreadable(string $reference, CatalogSkip $skip): self
    {
        return new self($reference, null, null, [$skip]);
    }

    /** How much of the picture this reading got. Derived, never asserted by a caller. */
    public function readability(): HeadroomReadability
    {
        return match (true) {
            $this->usedBytes instanceof Estimate && $this->freeBytes instanceof Estimate => HeadroomReadability::Complete,
            $this->usedBytes instanceof Estimate => HeadroomReadability::SizeOnly,
            default => HeadroomReadability::Unreadable,
        };
    }

    /**
     * Whether "will this fit" can be answered here at all.
     *
     * Named as a question about the READING rather than about the storage, deliberately. A consumer
     * asking `hasRoomFor($bytes)` on a reading with no free-space number would get `false` and read
     * it as "there is not enough room", which is a claim nobody measured. This method is what such a
     * consumer has to pass through first.
     */
    public function answersCapacity(): bool
    {
        return $this->readability()->answersCapacity();
    }

    /**
     * Whether a given number of bytes fits in what is left — or null when nobody can say.
     *
     * Three-valued for the reason the whole package is: the honest answer to "will 40 GB fit" on a
     * server that will not report free space is not "no". It is that the question was not answered,
     * and a gate that turned it into a refusal would block deploys on a fact it invented.
     */
    public function hasRoomFor(int $bytes): ?bool
    {
        $free = $this->freeBytes;

        return $free instanceof Estimate ? $free->value >= $bytes : null;
    }

    /**
     * @return array{reference: string, readability: string, used_bytes: array<string, mixed>|null, free_bytes: array<string, mixed>|null}
     */
    public function toArray(): array
    {
        return [
            'reference' => $this->reference,
            'readability' => $this->readability()->value,
            'used_bytes' => $this->usedBytes?->toArray(),
            'free_bytes' => $this->freeBytes?->toArray(),
        ];
    }

    private static function mustMeasure(string $slot, Estimate $estimate, EstimateSource $expected): void
    {
        if ($estimate->source !== $expected) {
            throw InvalidStatisticsReading::wrongQuantity($slot, $expected, $estimate->source);
        }
    }
}
