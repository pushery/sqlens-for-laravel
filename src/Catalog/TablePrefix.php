<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The Laravel table prefix, applied to a catalog reading.
 *
 * A project that set `prefix => 'acme_'` thinks in terms of `orders`. Its migrations say `orders`,
 * its models say `orders`, and a finding about `acme_orders` is a finding about a table the
 * developer does not believe they have. But `acme_orders` is what the database calls it, and a
 * reading that renamed it would be describing a schema that does not exist.
 *
 * So both names travel: the qualified name stays exactly what the catalog said, and the LOGICAL
 * name — schema-qualified, prefix removed — rides beside it as an attribute. A finding can quote
 * the name the user knows without the snapshot losing the identity the database uses.
 *
 * ## Why the prefix comes off the first segment after the schema
 *
 * `acme_orders`, `acme_orders.total`, `acme_orders_pkey`, `acme_orders_account_fk` — all four carry
 * it in the same place, because Laravel builds index and constraint names from the PREFIXED table
 * name. Stripping the leading prefix therefore yields `orders_pkey`, which is exactly what the
 * migration wrote. A rule that stripped it from the last segment instead would rename a column.
 */
final readonly class TablePrefix
{
    /**
     * The object kinds a user recognizes as "a thing in my database", and therefore the ones whose
     * exclusion is worth naming. A column's exclusion is implied by its table's.
     */
    private const array RELATION_TYPES = [
        SchemaObjectType::Table,
        SchemaObjectType::View,
        SchemaObjectType::MaterializedView,
        SchemaObjectType::Sequence,
    ];

    public function __construct(
        public string $prefix = '',
        public PrefixScope $scope = PrefixScope::Loose,
    ) {}

    /** Whether a prefix is configured at all — with none, every object is the project's own. */
    public function isSet(): bool
    {
        return $this->prefix !== '';
    }

    /**
     * Whether this object carries the prefix.
     *
     * Compared on the name segment that follows the schema, never on the qualified name as a whole:
     * a schema called `acme_data` would otherwise make every object in it look prefixed.
     */
    public function covers(string $qualifiedName): bool
    {
        if (! $this->isSet()) {
            return true;
        }

        return str_starts_with($this->objectPart($qualifiedName), $this->prefix);
    }

    /**
     * The name the project believes it has: schema-qualified, prefix removed.
     *
     * The TYPE is needed, because the two engines qualify an index differently — PostgreSQL names it
     * `schema.acme_orders_pkey` (an index is a schema-level object there) and MySQL names it
     * `schema.acme_orders.acme_orders_total_index` (keyed by its table). Measured, not assumed. The
     * prefix therefore has to come off every segment that carries it, which is right for a table, an
     * index and a constraint alike, since Laravel builds all three names from the PREFIXED table.
     *
     * A COLUMN is the exception and the reason the type is a parameter at all: its final segment is
     * a name the developer wrote by hand, so a column that happens to be called `acme_id` keeps its
     * name. Stripping there would rename a column nobody prefixed.
     *
     * An object that does not carry the prefix is returned untouched — its real name IS the name the
     * project knows it by, and inventing a difference would be worse than saying nothing.
     */
    public function logicalName(string $qualifiedName, SchemaObjectType $type = SchemaObjectType::Table): string
    {
        if (! $this->isSet() || ! $this->covers($qualifiedName)) {
            return $qualifiedName;
        }

        $segments = explode('.', $qualifiedName);
        $last = count($segments) - 1;

        foreach ($segments as $index => $segment) {
            // The first segment is the schema when there is more than one, and a schema is not
            // prefixed by Laravel — `acme_data.orders` must not become `data.orders`.
            if ($index === 0 && $last > 0) {
                continue;
            }

            // A column's final segment is a name somebody wrote by hand, so a column called
            // `acme_id` keeps it. Stripping there would rename a column nobody prefixed.
            if ($type === SchemaObjectType::Column && $index === $last) {
                continue;
            }

            if (str_starts_with($segment, $this->prefix)) {
                $segments[$index] = substr($segment, strlen($this->prefix));
            }
        }

        return implode('.', $segments);
    }

    /** Whether an object outside the prefix belongs in the reading at all. */
    public function admits(string $qualifiedName): bool
    {
        return $this->scope === PrefixScope::Loose || $this->covers($qualifiedName);
    }

    /**
     * The objects this prefix admits, each carrying the logical name and whether it is the
     * project's own — with what was left out named rather than silently missing.
     *
     * One skip per RELATION, never per column: an excluded table already answers "why is this not
     * in my audit?", and a skip per column would bury that answer under several hundred. The same
     * rule the extension filter follows, for the same reason.
     *
     * @param  list<SchemaObject>  $objects
     * @param  list<CatalogSkip>  $skips
     * @return list<SchemaObject>
     */
    public function applyTo(array $objects, array &$skips): array
    {
        if (! $this->isSet()) {
            return $objects;
        }

        $admitted = [];
        $covered = 0;

        foreach ($objects as $object) {
            if ($this->covers($object->qualifiedName)) {
                $covered++;
            } elseif (! $this->admits($object->qualifiedName)) {
                if (in_array($object->type, self::RELATION_TYPES, true)) {
                    $skips[] = CatalogSkip::for(
                        $object->type,
                        $object->qualifiedName,
                        SkipReason::ExcludedByConfig,
                        sprintf('does not carry the configured table prefix "%s", and prefix_scope is strict', $this->prefix),
                    );
                }

                continue;
            }

            $admitted[] = $object->withAttributes([
                'logical_name' => $this->logicalName($object->qualifiedName, $object->type),
                // Named on every object rather than only on the foreign ones: an attribute that
                // appears only when something is wrong cannot be relied on to be there when it is
                // right, and a reader would have to know that absence means "own".
                'prefixed' => $this->covers($object->qualifiedName),
            ]);
        }

        if ($covered === 0) {
            // The likeliest real cause is a prefix that is simply wrong — copied from another
            // project, or read from a connection the app does not use. An empty audit must not read
            // like a clean schema, so the reading says so and counts as partial.
            $skips[] = CatalogSkip::for(
                SchemaObjectType::Table,
                $this->prefix,
                SkipReason::PrefixMatchedNothing,
                sprintf('no object in the audited schemas carries the prefix "%s"', $this->prefix),
            );
        }

        return $admitted;
    }

    /** The name segment that follows the schema — the relation name, which is what carries a prefix. */
    private function objectPart(string $qualifiedName): string
    {
        $position = strpos($qualifiedName, '.');

        return $position === false ? $qualifiedName : substr($qualifiedName, $position + 1);
    }
}
