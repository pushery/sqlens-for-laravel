<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Catalog\Degradation\CatalogArea;
use Pushery\SQLens\Catalog\Degradation\PrivilegeProbe;

/**
 * Which parts of the catalog one engine lets a reading depend on, and how to ask.
 *
 * The two engines withhold in shapes that have nothing in common, so the QUESTIONS live per driver
 * while the policy — what an unreadable area means, and that it becomes a named skip rather than an
 * exception — stays in {@see PrivilegeProbe}.
 *
 * Measured on a role holding nothing but `USAGE`: PostgreSQL keeps `pg_class` world-readable and
 * refuses individual restricted views, while MySQL silently FILTERS `information_schema` down to
 * what the role may see — the same query, zero rows, no error. An interface that assumed one shape
 * would be blind on the other engine, which is why this asks each driver rather than generalizing.
 */
interface CatalogPrivileges
{
    /**
     * The areas to probe, each with a read-only, lock-free question that answers truthy when the
     * area is usable.
     *
     * @param  list<string>  $schemas  the scope the reading will cover — MySQL's visibility question
     *                                 is only meaningful against a concrete database
     * @return list<CatalogArea>
     */
    public function areas(array $schemas): array;
}
