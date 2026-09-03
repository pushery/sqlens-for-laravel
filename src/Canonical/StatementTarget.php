<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A schema object a canonical statement acts on: its object type and the
 * normalized Identifier from identifier normalization — so the schema and the name
 * stay SEPARATE and the qualified/unqualified information is preserved, never
 * flattened to a bare string. A `CREATE INDEX … ON …` yields two targets (the
 * index and its table); an `ADD CONSTRAINT … REFERENCES …` yields the altered
 * table and the referenced one.
 *
 * Driver-agnostic — it holds an already-parsed Identifier, so no engine syntax
 * lives here. `qualifiedName()` is the canonical, comparison-ready rendering the
 * drift comparator uses.
 */
final readonly class StatementTarget
{
    public function __construct(
        public SchemaObjectType $type,
        public Identifier $identifier,
        /**
         * What this target is TO the statement — see {@see TargetRole}.
         *
         * Defaulted, and that is what keeps the change small: every signature with one target of a
         * type declares nothing, every one of the 118 constructor calls in this repository is
         * positional, and only the three foreign-key signatures say anything else.
         */
        public TargetRole $role = TargetRole::Subject,
    ) {}

    /** Whether the statement ACTS on this object rather than merely pointing at it. */
    public function isSubject(): bool
    {
        return $this->role === TargetRole::Subject;
    }

    /** The canonical, comparison-ready name (schema-qualified when the source was). */
    public function qualifiedName(): string
    {
        return $this->identifier->canonical();
    }
}
