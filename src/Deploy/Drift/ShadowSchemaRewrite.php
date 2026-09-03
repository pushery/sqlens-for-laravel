<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

use Pushery\SQLens\Catalog\CatalogSnapshot;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * The throwaway database's name, taken back out of the expectation side.
 *
 * ## Why this exists, and it is not a nicety
 *
 * On MySQL the schema IS the database, so every qualified name carries it:
 * `sqlens_test.orders.id` live, `sqlens_shadow_20260819_ab12cd.orders.id` in the replay. The
 * comparator keys objects on `type + qualifiedName`, so the two sides can never meet — every object
 * is reported MISSING and UNEXPECTED at once.
 *
 * Measured on the first MySQL run there ever was: one undescribed table produced **44 unexpected and
 * 24 missing findings**, and two consecutive runs produced different reports, because the shadow name
 * carries a timestamp and a random suffix.
 *
 * PostgreSQL never showed it. There the schema is `public` on both sides, so the names happen to
 * agree — which is exactly why a proof on one engine is not a proof on the other.
 *
 * ## The rewrite belongs HERE, not in the comparator
 *
 * {@see DriftComparator} takes two readings and knows no engine, no connection and no database. That
 * is what keeps it honest. The reference builder is the one place holding both names at once — the
 * database it provisioned and the one it is standing in for — so the substitution happens before the
 * comparison ever sees the snapshot.
 *
 * ## It rewrites the QUALIFIER only, never a name that merely contains it
 *
 * Only a leading `<shadow>.` and an exact `<shadow>` parent are replaced. A table genuinely called
 * `sqlens_shadow_20260819_ab12cd_archive` keeps its name — a blind `str_replace` would rename it and
 * invent a difference in the very layer built to remove one.
 */
final readonly class ShadowSchemaRewrite
{
    /**
     * The snapshot as it would read had the replay happened in the source database.
     *
     * A no-op when the two names are equal or either is empty, which is the ordinary PostgreSQL
     * case: nothing is rewritten and no object is rebuilt.
     */
    public static function apply(CatalogSnapshot $snapshot, string $shadowDatabase, string $sourceDatabase): CatalogSnapshot
    {
        if ($shadowDatabase === '' || $sourceDatabase === '' || $shadowDatabase === $sourceDatabase) {
            return $snapshot;
        }

        return new CatalogSnapshot(
            $snapshot->context,
            array_map(
                static fn (SchemaObject $object): SchemaObject => self::rewrite($object, $shadowDatabase, $sourceDatabase),
                $snapshot->objects,
            ),
            $snapshot->skips,
        );
    }

    private static function rewrite(SchemaObject $object, string $shadow, string $source): SchemaObject
    {
        $qualified = str_starts_with($object->qualifiedName, $shadow.'.')
            ? $source.substr($object->qualifiedName, strlen($shadow))
            : $object->qualifiedName;

        // The parent is the schema itself on MySQL, so it is replaced whole rather than by prefix —
        // and only on an exact match, for the same reason the prefix test is anchored.
        $parent = match (true) {
            $object->parent === $shadow => $source,
            is_string($object->parent) && str_starts_with($object->parent, $shadow.'.') => $source.substr($object->parent, strlen($shadow)),
            default => $object->parent,
        };

        if ($qualified === $object->qualifiedName && $parent === $object->parent) {
            return $object;
        }

        return new SchemaObject(
            $object->type,
            $qualified,
            $parent,
            $object->attributes(),
            $object->context(),
            $object->fromExtension,
            $object->isPartition,
        );
    }
}
