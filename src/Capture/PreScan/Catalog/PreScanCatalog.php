<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan\Catalog;

use Pushery\SQLens\Capture\PreScan\CallTarget;

/**
 * One named catalog out of the bundled artifact — the entries a single detector
 * matches against.
 *
 * Order is the artifact's order, and matching returns the FIRST entry that hits.
 * That makes a specific target (`Illuminate\Support\Facades\DB::table`) able to
 * sit in front of a broad one (`Illuminate\Support\Facades\DB`) and win, without
 * the detector needing to know about precedence.
 */
final readonly class PreScanCatalog
{
    /**
     * @param  list<CatalogEntry>  $entries
     */
    public function __construct(
        public string $name,
        public string $description,
        public array $entries,
    ) {}

    /** The first entry this call hits, or null when the catalog does not cover it. */
    public function match(CallTarget $target): ?CatalogEntry
    {
        foreach ($this->entries as $entry) {
            if ($entry->target->matches($target)) {
                return $entry;
            }
        }

        return null;
    }

    /**
     * The families this catalog spans, in first-appearance order — the axis the
     * generated documentation groups by.
     *
     * @return list<string>
     */
    public function kinds(): array
    {
        $kinds = [];

        foreach ($this->entries as $entry) {
            if (! in_array($entry->kind, $kinds, true)) {
                $kinds[] = $entry->kind;
            }
        }

        return $kinds;
    }

    /** How many targets this catalog covers. */
    public function count(): int
    {
        return count($this->entries);
    }
}
