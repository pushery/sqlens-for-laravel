<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan\Catalog;

/**
 * One line of a pre-scan catalog: what to look for, which family it belongs to,
 * and why it matters.
 *
 * The reason travels WITH the entry rather than being composed by the detector,
 * so the sentence a user reads is the sentence a maintainer wrote next to the
 * target — a catalog whose reasons live in the code that consumes it drifts from
 * its own data on the first refactor.
 */
final readonly class CatalogEntry
{
    public function __construct(
        public CatalogTarget $target,
        public string $kind,
        public string $reason,
    ) {}
}
