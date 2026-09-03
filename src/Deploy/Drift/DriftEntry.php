<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * One disagreement between the two readings, at one object.
 *
 * ## The attribute diff is part of the finding, not a detail for later
 *
 * A `divergent` entry that said only "this column differs" would send its reader back to the two
 * databases to work out what — which is the work the comparison was supposed to have done. So the
 * changed attributes travel WITH the entry, each carrying both sides, and a reader can act without
 * opening a connection.
 *
 * The other two classes carry an empty diff, and that is not a gap: there is no second side to
 * compare against. What they carry instead is the object's own attributes, so "unexpected in the
 * database" comes with enough to write the migration that would have created it.
 */
final readonly class DriftEntry
{
    /**
     * @param  array<string, array{live: scalar|null, expected: scalar|null}>  $changes  attribute => both sides, for a divergence
     * @param  array<string, scalar|null>  $attributes  the object as the side that HAS it describes it
     */
    public function __construct(
        public DriftClass $class,
        public SchemaObjectType $type,
        public string $qualifiedName,
        public array $changes = [],
        public array $attributes = [],
    ) {}

    /**
     * The key two runs sort by, and it must not depend on the class.
     *
     * Sorting by class first would group the output by kind, which reads well and compares badly:
     * a schema where one object moved from `missing` to `divergent` would reorder every entry after
     * it, and a diff of two reports would show a change nobody made. Identity is stable; the class
     * is what changes.
     */
    public function sortKey(): string
    {
        return $this->type->value.':'.$this->qualifiedName;
    }
}
