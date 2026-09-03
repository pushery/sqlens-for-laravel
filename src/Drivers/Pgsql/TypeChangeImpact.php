<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql;

/**
 * What an `ALTER COLUMN … TYPE` does to the table, as far as the target type can tell.
 * Three-valued because the source type is not in the migration SQL: a target the matrix
 * knows to rewrite, a target it knows is free, or one it does not classify — which is
 * genuinely unknown, never assumed safe.
 */
enum TypeChangeImpact
{
    /** Forces a full-table rewrite under ACCESS EXCLUSIVE. */
    case Rewrite;

    /** A catalog-only change (the dominant case is varchar → text). */
    case MetadataOnly;

    /** The target type is not in the matrix — whether it rewrites is unknown. */
    case Unknown;
}
