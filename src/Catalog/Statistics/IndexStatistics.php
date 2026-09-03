<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Statistics;

use Pushery\SQLens\Exceptions\InvalidStatisticsReading;

/**
 * How much room one index takes.
 *
 * Its own type rather than an entry in a name-to-integer map, because the number is an
 * {@see Estimate} and has to stay one: the whole point of that type is that a size cannot travel
 * without saying how it was arrived at, and a map value is exactly where it would lose that.
 *
 * The size is the deploy gate's question about an index. Adding one to a large table is the
 * operation that takes the longest and the one whose cost a reader most wants weighted, and the
 * only honest input to that weighting is how big the existing ones already are.
 */
final readonly class IndexStatistics
{
    public function __construct(
        /** The index, qualified as the reading names it. */
        public string $qualifiedName,
        /**
         * Bytes this index occupies, or null when the reading could not establish it.
         *
         * Null is not zero and must never be read as it. An index whose size could not be read is
         * accompanied by a named skip on the snapshot; an index of zero bytes does not exist.
         */
        public ?Estimate $bytes = null,
    ) {
        if ($bytes instanceof Estimate && $bytes->source !== EstimateSource::IndexBytes) {
            throw InvalidStatisticsReading::wrongQuantity('index size', EstimateSource::IndexBytes, $bytes->source);
        }
    }

    /** @return array{name: string, bytes: array<string, mixed>|null} */
    public function toArray(): array
    {
        return [
            'name' => $this->qualifiedName,
            'bytes' => $this->bytes?->toArray(),
        ];
    }
}
