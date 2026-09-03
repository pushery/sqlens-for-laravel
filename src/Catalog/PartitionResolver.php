<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Folds a partitioned table's partitions onto the table itself.
 *
 * A partitioned table is ONE object to a rule and n objects in a catalog. Left unfolded, every
 * finding about it is reported once per partition — and a monthly-partitioned events table with
 * three years of history turns one finding into thirty-six. The first audit of a real database is
 * then unreadable, and there is no second one.
 *
 * ## Folding is not deletion
 *
 * The partitions do not vanish: they become a property of the parent, sorted, so the reading still
 * says what the database holds. And a partition that DIFFERS from its siblings — the classic case
 * being an index that exists on eleven partitions and not the twelfth — is recorded as a divergence
 * on the parent. That case is the reason to look at partitions at all, so a fold that dropped it
 * would remove the only information worth having.
 *
 * ## Driver-neutral, because the two engines disagree about what a partition even is
 *
 * On PostgreSQL a partition is a real table with its own catalog entry, its own indexes and its own
 * name. On MySQL it is not a table at all — `information_schema.TABLES` lists only the parent, and
 * the partitions live in a view of their own. So the drivers supply the parent map as DATA and this
 * class does the folding once, rather than each driver inventing its own idea of the result.
 */
final readonly class PartitionResolver
{
    /**
     * @param  array<string, string>  $parentOf  partition qualified name => the ROOT parent's
     *                                           qualified name, already resolved through any
     *                                           intermediate levels by the driver's own query — a
     *                                           sub-partition belongs to the table a user thinks
     *                                           in, not to the partition in between
     */
    public function __construct(private array $parentOf = []) {}

    /**
     * The objects with every partition folded onto its parent.
     *
     * @param  list<SchemaObject>  $objects
     * @return list<SchemaObject>
     */
    public function fold(array $objects): array
    {
        if ($this->parentOf === []) {
            return $objects;
        }

        $partitionsByParent = $this->partitionsByParent();
        $childObjects = $this->childObjectsByPartition($objects);

        $folded = [];

        foreach ($objects as $object) {
            // A partition's own table object disappears into its parent's list.
            if ($object->type === SchemaObjectType::Table && isset($this->parentOf[$object->qualifiedName])) {
                continue;
            }

            // Everything a partition OWNS — its columns, its indexes — moves to the parent rather
            // than being dropped. Dropping it would make a divergent partition invisible, which is
            // the one thing worth knowing about a partition set.
            if (isset($this->parentOf[$object->parent ?? ''])) {
                continue;
            }

            if ($object->type === SchemaObjectType::Table && isset($partitionsByParent[$object->qualifiedName])) {
                $folded[] = $this->withPartitions($object, $partitionsByParent[$object->qualifiedName], $childObjects);

                continue;
            }

            $folded[] = $object;
        }

        return $folded;
    }

    /**
     * The parent's object, now carrying its partitions and any divergence among them.
     *
     * @param  non-empty-list<string>  $partitions
     * @param  array<string, list<string>>  $childObjects  partition name => the index names it owns
     */
    private function withPartitions(SchemaObject $parent, array $partitions, array $childObjects): SchemaObject
    {
        sort($partitions);

        return $parent->withAttributes([
            'partitions' => implode(', ', $partitions),
            'partition_count' => count($partitions),
            // Named partitions rather than a boolean: "one of them differs" sends a reader looking
            // through all thirty-six, which is exactly the work the fold was meant to save them.
            'divergent_partitions' => implode(', ', $this->divergentAmong($partitions, $childObjects)),
        ]);
    }

    /**
     * The partitions whose index set differs from what the majority of their siblings carry.
     *
     * Compared against the SHAPE of an index rather than its name: every partition's copy of an
     * index has a name of its own, so comparing names would report all of them as divergent and the
     * signal would be worth nothing. What is compared is how many indexes each partition has —
     * coarse on purpose, because a finer comparison here would be a rule, and this layer has none.
     *
     * The partition list is never empty here — `fold()` only calls this for a parent it found
     * partitions for — so there is no empty-input arm. An arm nothing can reach would read as
     * covered while proving nothing about the case it appears to handle.
     *
     * @param  non-empty-list<string>  $partitions
     * @param  array<string, list<string>>  $childObjects
     * @return list<string>
     */
    private function divergentAmong(array $partitions, array $childObjects): array
    {
        $counts = [];

        foreach ($partitions as $partition) {
            $counts[$partition] = count($childObjects[$partition] ?? []);
        }

        $tally = array_count_values($counts);
        arsort($tally);
        $typical = array_key_first($tally);

        // With no count shared by at least two partitions there is no majority to diverge FROM, and
        // naming one of them would be a coin flip presented as a finding. Two partitions with
        // different index counts is the honest example: neither is the odd one out. Found by the
        // test — the first version picked whichever the tally happened to order first.
        if ($tally[$typical] < 2) {
            return [];
        }

        return array_keys(array_filter($counts, static fn (int $count): bool => $count !== $typical));
    }

    /** @return array<string, non-empty-list<string>> parent qualified name => its partitions */
    private function partitionsByParent(): array
    {
        $byParent = [];

        foreach ($this->parentOf as $partition => $parent) {
            $byParent[$parent][] = $partition;
        }

        return $byParent;
    }

    /**
     * The index names each partition owns — the material a divergence is read from.
     *
     * @param  list<SchemaObject>  $objects
     * @return array<string, list<string>>
     */
    private function childObjectsByPartition(array $objects): array
    {
        $owned = [];

        foreach ($objects as $object) {
            $parent = $object->parent ?? '';

            if ($object->type === SchemaObjectType::Index && isset($this->parentOf[$parent])) {
                $owned[$parent][] = $object->qualifiedName;
            }
        }

        return $owned;
    }
}
