<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\OnlineDdl;

/**
 * The provenance of one matrix entry: where the fact was read and when. Every entry must
 * carry at least one, which is what keeps the matrix a cited artifact rather than an
 * unsourced claim — the schema rejects an entry without one.
 */
final readonly class MatrixSource
{
    public function __construct(
        public string $url,
        public string $anchor,
        public string $retrieved,
    ) {}
}
