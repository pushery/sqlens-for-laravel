<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Pushery\SQLens\Catalog\Canonical\CatalogObjectFingerprint;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * One reading of a live catalog: what was found, what was NOT, where it came from, and whether it
 * is the whole picture.
 *
 * The four parts are inseparable on purpose. A collection of objects alone cannot be judged (which
 * server? which schemas?), cannot be compared (against a reading of what scope?), and — worst —
 * cannot be told apart from a reading that saw half the database, because a half-read catalog looks
 * exactly like a clean one to everything downstream.
 *
 * ## Determinism is a property of the type, not of the reader
 *
 * The objects and the skips are sorted HERE, on construction, rather than left to whichever order
 * the catalog query happened to return. Two readings of an unchanged database must serialize
 * byte-identically, or the drift comparator reports the ordering of a query plan as a schema change
 * — noise that trains its reader to ignore it. Sorting in one place means no reader can forget, and
 * no reader can sort differently.
 *
 * ## Completeness is derived, never asserted
 *
 * A caller does not get to say a reading was complete. It is computed from the skips: a reading
 * that dropped something for any reason other than a deliberate exclusion is `partial`. That
 * direction matters — an optimistic reader could otherwise report `complete` while its own skip
 * list contradicted it, and the field would be worth less than nothing.
 */
final readonly class CatalogSnapshot
{
    /** @var list<SchemaObject> */
    public array $objects;

    /** @var list<CatalogSkip> */
    public array $skips;

    public CatalogCompleteness $completeness;

    /**
     * @param  list<SchemaObject>  $objects
     * @param  list<CatalogSkip>  $skips
     */
    public function __construct(
        public CatalogContext $context,
        array $objects = [],
        array $skips = [],
    ) {
        $skips = $this->condensed($skips);

        usort($objects, static fn (SchemaObject $a, SchemaObject $b): int => self::objectSortKey($a) <=> self::objectSortKey($b));
        usort($skips, static fn (CatalogSkip $a, CatalogSkip $b): int => $a->sortKey() <=> $b->sortKey());

        $this->objects = $objects;
        $this->skips = $skips;
        $this->completeness = $this->completenessOf($skips);
    }

    /**
     * One entry per (extension, kind) instead of one per excluded object.
     *
     * ## Why the skip list needed this
     *
     * It is where a reader looks to find out what could NOT be checked, and that purpose is defeated
     * by volume. Measured on the smallest extension in the fixture tree: reading routines took the
     * list from 4 entries to 35, and 31 of those were `pg_trgm` saying the same thing 31 times.
     * PostGIS ships over a thousand functions, so a project using it would get a four-digit list —
     * in the one place the genuinely unread objects are supposed to stand out.
     *
     * ## Why HERE, and why it applies to every kind
     *
     * Same argument the sorting two lines above makes: one place means no reader can forget and no
     * reader can do it differently. Doing it in the PostgreSQL reader would have left the MySQL one
     * free to diverge; doing it in a reporter would put extension knowledge in the output layer and
     * leave a JSON consumer with the flood.
     *
     * It condenses per KIND rather than per extension alone, because the kind is the part a reader
     * acts on: a skipped TABLE is a different conversation from a skipped function.
     *
     * ## What is not lost
     *
     * The extension is named, the kind is named, the count is exact, and the reason is unchanged.
     * That is strictly more than the list gave — the list made the count something a reader had to
     * work out. A single excluded object is left alone: naming it is clearer than counting it.
     *
     * Only `excluded_by_config` skips that name an owning extension are touched. Everything that
     * made the reading incomplete is a gap rather than a decision, and a gap is never condensed —
     * those are the entries the list exists for.
     *
     * @param  list<CatalogSkip>  $skips
     * @return list<CatalogSkip>
     */
    private function condensed(array $skips): array
    {
        $groups = [];
        $kept = [];

        foreach ($skips as $skip) {
            if ($skip->reason !== SkipReason::ExcludedByConfig || $skip->owningExtension === null) {
                $kept[] = $skip;

                continue;
            }

            $groups[$skip->owningExtension."\0".$skip->type->value][] = $skip;
        }

        foreach ($groups as $group) {
            if (count($group) === 1) {
                $kept[] = $group[0];

                continue;
            }

            $first = $group[0];

            $kept[] = CatalogSkip::extensionScope(
                $first->type,
                (string) $first->owningExtension,
                count($group),
                (string) ($first->detail ?? 'excluded from this reading'),
            );
        }

        return $kept;
    }

    /** Whether anything in scope went unread — the question a consumer must ask before trusting silence. */
    public function isPartial(): bool
    {
        return $this->completeness === CatalogCompleteness::Partial;
    }

    /**
     * The skips that made this reading partial — the ones where something in scope went UNREAD.
     *
     * A caller reporting "why is this partial?" wants these and not the deliberate exclusions or the
     * comprehension limits, which are decisions and rule-level facts rather than gaps and would bury
     * the real answer under expected noise. Both are still in `$skips`, so nothing disappears — a
     * reporter listing everything the reading has to say still shows them.
     *
     * @return list<CatalogSkip>
     */
    public function gaps(): array
    {
        return array_values(array_filter(
            $this->skips,
            static fn (CatalogSkip $skip): bool => $skip->reason->leavesTheReadingIncomplete(),
        ));
    }

    /**
     * A stable digest of this reading.
     *
     * The context is part of it: two readings that differ only in the schemas they scoped are
     * different readings, and a hash that ignored that would let a comparator treat them as the
     * same picture of the same database.
     */
    public function hash(): string
    {
        return hash('sha256', $this->serialize());
    }

    /**
     * The canonical serialization — the one a hash is taken over and the one a golden file holds.
     *
     * `JSON_THROW_ON_ERROR` rather than a silent `false`: a snapshot that could not be serialized
     * must not become an empty digest that two different databases would share.
     */
    public function serialize(): string
    {
        return json_encode($this->toArray(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * @return array{context: array<string, mixed>, completeness: string, objects: list<array{type: string, name: string, parent: string|null, from_extension: bool, is_partition: bool}>, skips: list<array<string, mixed>>}
     */
    public function toArray(): array
    {
        return [
            'context' => $this->context->toArray(),
            'completeness' => $this->completeness->value,
            'objects' => array_map(
                static fn (SchemaObject $object): array => [
                    'type' => $object->type->value,
                    'name' => $object->qualifiedName,
                    'parent' => $object->parent,
                    // What the object IS, not merely that it exists. Without this a comparison over
                    // two readings sees a table appear or vanish and nothing else — not a changed
                    // column type, not a changed default, not a reordered index. The attributes
                    // arrive already canonicalized: the reader runs defaults and collations through
                    // the canonicalizer as it reads them, so two servers spelling one default
                    // differently serialize the same here.
                    //
                    // Sorted by the object itself, and filtered by the register above: three of
                    // these keys move without the schema moving, and a comparison that read them
                    // would report drift on an untouched database.
                    'attributes' => CatalogObjectFingerprint::comparableAttributes($object),
                    'from_extension' => $object->fromExtension,
                    'is_partition' => $object->isPartition,
                ],
                $this->objects,
            ),
            'skips' => array_map(static fn (CatalogSkip $skip): array => $skip->toArray(), $this->skips),
        ];
    }

    /**
     * Schema → object type → name, as one comparable string.
     *
     * The parent leads because it is the schema (or the owning table) an object belongs to, which
     * groups a reading the way a human reads one; the type comes before the name so two objects of
     * different kinds with the same name never interleave.
     */
    private static function objectSortKey(SchemaObject $object): string
    {
        return ($object->parent ?? '').':'.$object->type->value.':'.$object->qualifiedName;
    }

    /** @param  list<CatalogSkip>  $skips */
    private function completenessOf(array $skips): CatalogCompleteness
    {
        $unread = array_any($skips, static fn (CatalogSkip $skip): bool => $skip->reason->leavesTheReadingIncomplete());

        return $unread ? CatalogCompleteness::Partial : CatalogCompleteness::Complete;
    }
}
