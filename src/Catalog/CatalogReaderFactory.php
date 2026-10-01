<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Closure;
use Illuminate\Database\Connection;
use Pushery\SQLens\Exceptions\UnsupportedCatalogDriver;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * Builds the catalog readers for a connection — the ONE place that knows which engine gets which.
 *
 * Everything downstream of it is driver-neutral by construction: the audit runner asks for readers
 * by connection name and never learns what answered. Without this the branch would appear in the
 * runner, in the settings reader and in the report header, and each copy would be a place the two
 * engines could drift apart.
 *
 * ## Why the builders are registered rather than hard-coded here
 *
 * `src/Catalog` is core, and the architecture test keeps core free of driver imports. A `match` on
 * `'pgsql'` naming `PgsqlCatalogReader` would put a driver class in core — the coupling moved into
 * a string, which is exactly what that test exists to catch. So each driver registers its own
 * builder at boot, and this class holds only the map.
 */
final class CatalogReaderFactory
{
    /** @var array<string, Closure(Connection, SessionBudget, SubjectContext): CatalogReaders> */
    private array $builders = [];

    /**
     * Register the builder for one driver key.
     *
     * The builder is handed a CONNECTION rather than a session, and builds the session itself. The
     * session's read-only seal and its timeouts are engine-specific too — PostgreSQL and MySQL seal
     * a session differently — so a factory that took a ready-made session would have pushed that
     * branch back out to every caller, which is the one thing this class exists to prevent.
     *
     * @param  Closure(Connection, SessionBudget, SubjectContext): CatalogReaders  $builder
     */
    public function register(string $driver, Closure $builder): void
    {
        $this->builders[$driver] = $builder;
    }

    /** Whether this factory can build readers for the driver. */
    public function supports(string $driver): bool
    {
        return array_key_exists($driver, $this->builders);
    }

    /**
     * The readers for this driver, over a session this factory opens for them.
     *
     * Throws rather than returning null for an unknown driver, and that is deliberate: reaching
     * here means the instance resolver already accepted the connection, so an unregistered driver
     * at this point is a wiring bug in this package, not a user's misconfiguration. A null would
     * travel one more layer before failing, with nothing left that knows why.
     *
     * @throws UnsupportedCatalogDriver
     */
    public function for(string $driver, Connection $connection, SessionBudget $budget, SubjectContext $context): CatalogReaders
    {
        $builder = $this->builders[$driver] ?? null;

        if (! $builder instanceof Closure) {
            throw new UnsupportedCatalogDriver($driver, array_keys($this->builders));
        }

        return $builder($connection, $budget, $context);
    }
}
