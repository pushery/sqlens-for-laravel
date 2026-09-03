<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Pushery\SQLens\Engine\ResolvedServerVersion;
use Pushery\SQLens\Exceptions\InvalidCatalogSnapshot;
use Pushery\SQLens\Rules\ServerVersion;

/**
 * Where a catalog snapshot came from — carried by the snapshot as a REQUIRED field, not attached
 * to it afterwards.
 *
 * Two things downstream break without it, and both break silently:
 *
 * - **A level-5-to-7 rule has a `minVersion`/`maxVersion` and nothing to resolve it against.** A
 *   rule that cannot tell which server it is judging either applies everywhere (wrong on the
 *   versions it was not written for) or nowhere (a silent skip). The version gate needs a version,
 *   and the snapshot is where it comes from.
 * - **The drift comparator would compare snapshots of unknown origin.** Two readings of "the same"
 *   database taken through different schema scopes or different table prefixes are not comparable,
 *   and a diff between them is noise presented as change.
 *
 * ## The raw banner AND the parsed version, both
 *
 * `18.2 (Debian 18.2-1.pgdg120+1)` and `8.4.10` are what a server actually reports, and the parsed
 * form throws away everything but the numbers. Keeping only the parse would lose the build a report
 * has to be able to name; keeping only the banner would make every rule parse it again, differently.
 * So both travel, and the parsed one is the one a rule branches on.
 *
 * ## What it says about a pin, and what it does not
 *
 * A run may reason about an `assume_server_version` PIN rather than the live server. The pin itself
 * is not built here — this type carries its EFFECT: which version the reading reflects, whether that
 * came from the connection or from configuration, and whether the two disagreed. A rule branches on
 * the version alone, never on its source; the source travels so a report can say what it reflected.
 */
final readonly class CatalogContext
{
    /**
     * @param  list<string>  $schemas  the schemas actually read, in the order the request scoped them
     */
    private function __construct(
        public string $driver,
        /** The server's banner, verbatim — the build a report must be able to name. */
        public string $serverVersionRaw,
        /** The version a rule branches on: the pin where one applies, else the detected version. */
        public ServerVersion $serverVersion,
        /** How the version above was arrived at, and whether a pin disagreed with the server. */
        public ResolvedServerVersion $resolvedServerVersion,
        public array $schemas,
        /**
         * The table prefix in force for this reading, `''` when none is.
         *
         * Part of the context rather than of the request, because what matters downstream is what
         * was APPLIED: a snapshot read with a prefix and one read without it describe different
         * object sets, and a comparator that did not know would report the difference as drift.
         */
        public string $tablePrefix,
    ) {}

    /**
     * @param  list<string>  $schemas
     *
     * The driver and the version are required, and an empty driver is refused rather than stored:
     * a snapshot that cannot say which engine it describes is one no rule can safely judge, and the
     * failure would surface much later as a rule quietly not firing.
     */
    public static function of(
        string $driver,
        string $serverVersionRaw,
        ResolvedServerVersion $resolvedServerVersion,
        array $schemas,
        string $tablePrefix = '',
    ): self {
        if (trim($driver) === '') {
            throw new InvalidCatalogSnapshot('A catalog context needs the driver it was read through.');
        }

        $version = $resolvedServerVersion->version;

        if (! $version instanceof ServerVersion) {
            throw new InvalidCatalogSnapshot(
                'A catalog context needs a resolved server version. A reading whose version could not be '
                .'determined is an undetermined result, not a snapshot: the level-5-to-7 rules have a version '
                .'window and nothing to resolve it against.',
            );
        }

        return new self($driver, $serverVersionRaw, $version, $resolvedServerVersion, $schemas, $tablePrefix);
    }

    /** Whether the reading reflects a pin that disagreed with the connected server. */
    public function hasVersionSkew(): bool
    {
        return $this->resolvedServerVersion->hasSkew();
    }

    /**
     * @return array{driver: string, server_version: string, server_version_raw: string, version_source: string, version_skew: bool, schemas: list<string>, table_prefix: string}
     */
    public function toArray(): array
    {
        return [
            'driver' => $this->driver,
            'server_version' => $this->serverVersion->toString(),
            'server_version_raw' => $this->serverVersionRaw,
            'version_source' => $this->resolvedServerVersion->source->value,
            'version_skew' => $this->hasVersionSkew(),
            'schemas' => $this->schemas,
            'table_prefix' => $this->tablePrefix,
        ];
    }
}
