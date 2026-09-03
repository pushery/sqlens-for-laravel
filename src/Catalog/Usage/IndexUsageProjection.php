<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Usage;

use Pushery\SQLens\Catalog\TableMembers;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Puts each table's index scan counts where a rule can see them.
 *
 * ## Why this is a separate step and not part of TableMembers
 *
 * {@see TableMembers} runs INSIDE the catalog reading, over facts that came
 * from the same query battery. Usage counters come from a different reading entirely — a second
 * accessor on the reader contract, deliberately kept out of the snapshot because they move while
 * the schema stands still. Attaching them there would mean the snapshot could no longer promise
 * that two readings of an unchanged database are identical.
 *
 * So the audit runner reads the catalog, reads the usage, and joins the two here.
 *
 * ## What an absence means, and it is three different things
 *
 * The encoding has to keep three cases apart, because a rule that confused any two of them would
 * recommend dropping an index on no evidence:
 *
 * - **The statistics could not be read at all** — no attribute is attached. `performance_schema` is
 *   off, or the role cannot see the view.
 * - **They were read, and this index is not among them** — the index is absent from the list. It
 *   was not counted; that is not the same as counted and never used.
 * - **They were read and this index has a count** — `name(0)` is a fact, and the only one of the
 *   three a verdict may rest on.
 */
final readonly class IndexUsageProjection
{
    /**
     * Every table with its index scan counts and the statistics window attached.
     *
     * @param  list<SchemaObject>  $objects
     * @return list<SchemaObject>
     */
    public static function attachTo(array $objects, IndexUsageReading $usage): array
    {
        if (! $usage->available) {
            // Nothing attached at all. An empty projection would read as "counted, and never used",
            // which is the one reading that must never be inferred from a gap.
            return $objects;
        }

        $perTable = [];

        foreach ($objects as $object) {
            if ($object->type !== SchemaObjectType::Index) {
                continue;
            }

            $scans = $usage->scansOf($object->qualifiedName);

            if ($scans !== null) {
                $perTable[$object->parent ?? ''][] = self::shortName($object).'('.$scans.')';
            }
        }

        $attached = [];

        foreach ($objects as $object) {
            if ($object->type !== SchemaObjectType::Table) {
                $attached[] = $object;

                continue;
            }

            $entries = $perTable[$object->qualifiedName] ?? [];
            sort($entries);

            $attached[] = $object->withAttributes([
                'index_scans' => implode('; ', $entries),
                // The server's own spelling, carried so a finding can quote it. Empty means the
                // counters were never reset and the window therefore starts at a moment nobody
                // recorded — measured as the ordinary state of a fresh PostgreSQL cluster, and the
                // permanent state on MySQL, which has no reset point at all.
                'index_stats_reset_at' => $usage->statsResetAt ?? '',
                // WHOLE days, computed by the server. Whole rather than an instant so two audits on
                // the same day still produce byte-identical output; the server's clock rather than
                // PHP's because it is the one that stamped the reset the count is measured from.
                'index_stats_window_days' => $usage->windowDays ?? -1,
            ]);
        }

        return $attached;
    }

    /**
     * The index's name without the qualification its table already carries.
     *
     * The same two-prefix strip {@see TableMembers} uses, and for the same
     * measured reason: MySQL keys an index by its TABLE and PostgreSQL by its SCHEMA, so stripping
     * only one of them leaves every entry on the other engine carrying a prefix nobody wants to
     * read — and, worse, not matching the names the other projections use.
     */
    private static function shortName(SchemaObject $index): string
    {
        $name = $index->qualifiedName;
        $parent = $index->parent ?? '';
        $schema = str_contains($parent, '.') ? substr($parent, 0, (int) strrpos($parent, '.')) : $parent;

        foreach ([$parent, $schema] as $prefix) {
            if ($prefix !== '' && str_starts_with($name, $prefix.'.')) {
                return substr($name, strlen($prefix) + 1);
            }
        }

        return $name;
    }
}
