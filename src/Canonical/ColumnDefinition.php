<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

use Pushery\SQLens\Catalog\Canonical\CanonicalType;

/**
 * One column a migration statement DEFINES, with the type it defines it as.
 *
 * ## Why this is not the same thing as `keyColumns`
 *
 * {@see MigrationStatementDigest::$keyColumns} is an ordered list of NAMES — an index's key
 * columns, a foreign key's referencing columns — and it exists for the left-prefix question.
 * This says what a column IS, which is the question every type rule asks and which no lint run
 * could ask before: the column list a `CREATE TABLE` writes never reached the digest at all, so
 * a rule needing a column type was structurally audit-only. Not because that was the right
 * answer — the migration that introduces a wrong type is the cheapest moment to fix it — but
 * because the question could not be put.
 *
 * ## The type goes through the SAME normalizer the catalog uses
 *
 * {@see CanonicalType::fromRaw()}, the one the catalog reader calls on `format_type()`'s answer.
 * That is not tidiness: a lint verdict and an audit verdict about the same column must not be
 * able to differ, and two normalizers are two answers. It already speaks both vocabularies —
 * `bigserial` and `bigint` land on the same name, so do `varchar` and `character varying` — which
 * is why there is no mapping table here and must never be one.
 *
 * ## Null is "could not be read", never "has none"
 *
 * Every column has a type. A definition whose type this layer could not make sense of arrives
 * with a null one and is still PRESENT, because the two are different answers for a rule: an
 * absent column is one a rule stays silent about, and an unread type is one it must report as
 * undetermined. Dropping the column would collapse the second into the first, which is the
 * silent direction.
 */
final readonly class ColumnDefinition
{
    public function __construct(
        /** The column's own name, as the statement spells it. */
        public string $name,
        /** What it is, or null where the type could not be read. */
        public ?CanonicalType $type = null,
    ) {}

    /** Whether the type could be read at all. */
    public function typed(): bool
    {
        return $this->type instanceof CanonicalType;
    }

    /**
     * Whether this column is of the given canonical type.
     *
     * False for an unread type, and a caller that needs to tell "no" from "cannot say" asks
     * {@see self::typed()} first. Named rather than left to `->type?->is()` so the null case has
     * one meaning at every call site instead of whichever the caller happened to write.
     */
    public function isOfType(string $canonicalName): bool
    {
        return $this->type?->is($canonicalName) ?? false;
    }
}
