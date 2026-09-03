<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Catalog;

/**
 * Decides which extension-owned objects belong in a reading — by OWNERSHIP, never by name.
 *
 * An object installed by `postgis` or `pg_trgm` is not the user's. Auditing it is the classic
 * false-positive source: PostGIS alone installs dozens of tables, and a rule about missing primary
 * keys will report every one of them, on a database whose owner wrote none of it.
 *
 * ## Ownership, not a name list
 *
 * The temptation is a list of known extension prefixes. It catches the extensions somebody thought
 * of and nothing else — and it catches a user's own `postgis_backup` table by accident. PostgreSQL
 * already records the truth: `pg_depend.deptype = 'e'` means "this object exists because that
 * extension does". That is a fact about the database rather than a guess about a name, and it
 * covers the extension nobody on this project has heard of.
 *
 * ## Excluded means NAMED as excluded
 *
 * Every object left out becomes a skip carrying the extension that owns it. A count of what was
 * excluded and why is the difference between a scope decision and a silent absence — and it is what
 * lets someone ask "why does the audit not mention my spatial tables?" and get an answer.
 */
final readonly class ExtensionOwnershipFilter
{
    /**
     * @param  bool  $includeAll  the escape hatch for a project that genuinely audits its
     *                            extensions — off by default, because for almost everyone those
     *                            objects are somebody else's code
     * @param  list<string>  $allowed  extensions whose objects ARE the user's business, named one by
     *                                 one. The per-extension form matters: a project that manages
     *                                 its own `citext` domains should not have to take PostGIS's
     *                                 hundred tables with it.
     */
    public function __construct(
        private bool $includeAll = false,
        private array $allowed = [],
    ) {}

    /**
     * Whether an object owned by the named extension belongs in the reading.
     *
     * An object owned by NOTHING (an empty name) is the user's own and always included — the filter
     * only ever decides about objects the catalog says belong to an extension.
     */
    public function includes(string $owningExtension): bool
    {
        if ($owningExtension === '') {
            return true;
        }

        return $this->includeAll || in_array($owningExtension, $this->allowed, true);
    }

    /** The reason line a skip carries, so an exclusion can be traced to the decision behind it. */
    public function reasonFor(string $owningExtension): string
    {
        return sprintf('owned by the %s extension, which this reading does not audit', $owningExtension);
    }
}
