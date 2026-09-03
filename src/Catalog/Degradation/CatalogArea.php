<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Degradation;

/**
 * One part of the catalog a reading depends on, and the question that decides whether it is there.
 *
 * The area is named in the user's terms — "indexes", "table statistics" — rather than in the
 * server's, because the skip a reader ends up holding has to say what is MISSING FROM THE AUDIT.
 * `pg_statistic is not readable` is a fact about a catalog table; `table statistics` is the thing
 * that will not be reasoned about, and the second one is what a person can act on.
 */
final readonly class CatalogArea
{
    /**
     * @param  string  $name  what a reader loses when this area is unreadable, in their words
     * @param  string  $sql  a query returning ONE row with ONE truthy-or-falsy column. It must be
     *                       read-only and lock-free — the probe runs on a production database whose
     *                       owner has not agreed to anything beyond being looked at.
     * @param  string  $consequence  the sentence that says what the audit cannot conclude without it
     * @param  list<string>  $bindings  the query's bindings, if it is scoped to the read's schemas
     */
    public function __construct(
        public string $name,
        public string $sql,
        public string $consequence,
        public array $bindings = [],
    ) {}
}
