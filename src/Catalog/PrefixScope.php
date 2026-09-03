<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

/**
 * What a configured table prefix does to the SCOPE of a reading.
 *
 * A Laravel project with `prefix => 'acme_'` shares its database with something in two ordinary
 * situations: a second application in the same schema, and its own legacy tables from before the
 * prefix existed. Those two want opposite answers, so this is a decision the project makes rather
 * than one the reader makes for it.
 */
enum PrefixScope: string
{
    /**
     * Read everything, and MARK what does not carry the prefix. The default.
     *
     * Chosen rather than fallen into, and the reasoning is the package's own doctrine: of the two
     * ways to be wrong here, omitting objects is the worse one. A `strict` default would silently
     * drop a project's own unprefixed legacy tables — an audit that misses the tables it exists to
     * examine, and reports clean while doing it. `loose` can only be wrong in the visible
     * direction: findings about a co-tenant's tables, each one marked as not the project's, which a
     * reader can see and filter. Noise is recoverable; a silent omission is not.
     */
    case Loose = 'loose';

    /**
     * Read ONLY objects carrying the prefix.
     *
     * The deliberate narrowing for a genuinely shared database, where everything unprefixed belongs
     * to somebody else and reporting on it is worse than useless. What it drops is still counted:
     * the objects left out become a named exclusion rather than a silent absence.
     */
    case Strict = 'strict';
}
