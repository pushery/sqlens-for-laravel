<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

/**
 * Which schemas a reading covers — resolved, checked, and never assumed.
 *
 * The assumption this class exists to remove is `public`. A multi-tenant application, or one that
 * keeps a module per schema, has almost nothing there — so a reader that assumed it would produce a
 * confident, complete-looking audit of the wrong half of the database. The default is therefore the
 * session's REAL resolved scope (PostgreSQL's `search_path` as the server expands it, MySQL's
 * current database), and the driver supplies that as data.
 *
 * ## A typo is an error, not an empty result
 *
 * `schemas => ['tenat_42']` must not read nothing and report a clean run. That is the shape of
 * every silent no-op: the tool did exactly what it was told, and what it was told was wrong. A
 * requested schema that does not exist on the server is a configuration error naming the schema and
 * listing what is actually there.
 *
 * ## So is a default that resolves to nothing
 *
 * The same no-op has an ordinary cause when nothing is named. PostgreSQL's `current_schemas(false)`
 * leaves out every schema the reading role has no `USAGE` on: measured on 18.4, a `pg_monitor` role
 * with the path set to `app` resolves `{}`, and so does a hardened `"$user", public` without usage
 * on `public`. On MySQL a Laravel connection configured with `'database' => ''` opens, and
 * `DATABASE()` answers `NULL` (measured on 8.4.10). Either way the reading would cover no schema at
 * all, so an empty default is refused like a typo, with what the session resolved and what exists.
 *
 * ## A system schema is refused rather than dropped
 *
 * `pg_catalog` and `information_schema` are the server's own bookkeeping; auditing them would report
 * hundreds of findings about tables nobody in the project wrote. They never appear in a snapshot —
 * but a config that explicitly NAMES one is refused rather than quietly narrowed, because silently
 * removing a schema somebody asked for is the same silent no-op as the typo above. Filtering them
 * out of the DEFAULT scope is different and stays silent: nobody asked for them there, a
 * `search_path` did.
 *
 * ## No implicit fan-out
 *
 * Reading a scope never discovers a sibling. A tenant-per-schema application that names two tenants
 * gets those two, not every tenant that happens to exist — the connection and the schemas are an
 * explicit statement, and an audit that quietly widened its own scope would be reporting on
 * databases nobody asked about.
 */
final readonly class SchemaScope
{
    /**
     * @param  list<string>  $requested  the schemas the caller named; empty means "the reader's
     *                                   resolved default"
     * @param  list<string>  $systemSchemas  the driver's own bookkeeping schemas, which are never
     *                                       part of a reading
     */
    public function __construct(
        private array $requested,
        private array $systemSchemas,
    ) {}

    /**
     * The schemas to read, checked against the server.
     *
     * @param  list<string>  $resolvedDefault  what the session itself resolves as its scope
     * @param  list<string>  $existing  every schema the server actually has
     * @return list<string>
     *
     * @throws UnknownCatalogSchema when a requested schema does not exist or is the server's own, or
     *                              when the default resolves to no schema the server has
     */
    public function apply(array $resolvedDefault, array $existing): array
    {
        if ($this->requested === []) {
            // The default is filtered, not checked: a `search_path` entry for a schema that does not
            // exist is legal and ordinary in PostgreSQL (`"$user"` on a database without one), so
            // treating it as a configuration error would fail runs nobody misconfigured.
            $schemas = array_values(array_filter(
                $resolvedDefault,
                fn (string $schema): bool => ! $this->isSystem($schema) && in_array($schema, $existing, true),
            ));

            // …but a default that leaves NOTHING is the typo's silent no-op arriving through the
            // other door: the reading would cover no schema and report a clean run. It happens with
            // an ordinary setup, which is why it is refused rather than tolerated.
            if ($schemas === []) {
                throw UnknownCatalogSchema::defaultResolvedToNothing(
                    $resolvedDefault,
                    array_values(array_filter($existing, fn (string $schema): bool => ! $this->isSystem($schema))),
                );
            }

            return $schemas;
        }

        foreach ($this->requested as $schema) {
            if ($this->isSystem($schema)) {
                throw UnknownCatalogSchema::isTheServersOwn($schema);
            }

            if (! in_array($schema, $existing, true)) {
                throw UnknownCatalogSchema::doesNotExist($schema, $existing);
            }
        }

        return $this->requested;
    }

    private function isSystem(string $schema): bool
    {
        return in_array($schema, $this->systemSchemas, true);
    }
}
