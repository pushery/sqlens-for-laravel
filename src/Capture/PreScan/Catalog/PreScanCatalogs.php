<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan\Catalog;

use JsonException;
use Pushery\SQLens\Exceptions\InvalidPreScanCatalog;

/**
 * The bundled pre-scan catalog artifact, loaded and validated.
 *
 * The catalogs are DATA, not arrays scattered through the detectors. Three
 * reasons, in the order they bite:
 *
 * 1. A maintained list of dangerous surfaces has to be reviewable as a list. A
 *    diff of `resources/data/prescan-catalogs.json` shows exactly which target
 *    was added or dropped; a diff across four detector classes does not.
 * 2. The side-effect catalog NAMES the surfaces it warns about — `curl_exec`,
 *    `file_put_contents`, `Http::get`. Inside `src/` a scanner cannot tell the
 *    name of a dangerous call from a dangerous call, so the package's own
 *    no-network guard would have to be weakened to hold the list. Keeping the
 *    names outside the code keeps that guard undiluted.
 * 3. The artifact carries its own schema version, so a later shape change is a
 *    visible, versioned migration rather than a silent reinterpretation of the
 *    same file.
 *
 * Validation is total and loud. A missing key, a wrong type, an unparseable
 * target, a duplicate — each is a named error at load. A catalog that quietly
 * dropped half its entries would leave the pre-scan blind on exactly the
 * surfaces it exists to watch, and it would look green while doing it.
 */
final class PreScanCatalogs
{
    /** The artifact's file name under `resources/data`. */
    public const string ARTIFACT = 'prescan-catalogs.json';

    /** The artifact shape this build implements. */
    public const int SCHEMA_VERSION = 1;

    /** Classes an indirect-call hit is deliberately not raised for. */
    public const string INDIRECT_CALL_EXEMPT = 'indirect_call_exempt';

    /** Schema-introspection calls whose answer pretend mode cannot give truthfully. */
    public const string INTROSPECTION_GUARDS = 'introspection_guards';

    /** Surfaces that reach outside the database — the ones a lint run must never touch. */
    public const string SIDE_EFFECTS = 'side_effects';

    /** Calls whose result decides what SQL a migration emits. */
    public const string RESULT_DEPENDENT = 'result_dependent';

    /** Surfaces that share a result-dependent method name without reading the database. */
    public const string RESULT_DEPENDENT_EXEMPT = 'result_dependent_exempt';

    /** The calls that put DDL or data changes into a migration. */
    public const string DDL_EMITTERS = 'ddl_emitters';

    private static ?self $default = null;

    /**
     * @param  array<string, PreScanCatalog>  $catalogs
     */
    private function __construct(
        public readonly string $origin,
        public readonly int $schemaVersion,
        private readonly array $catalogs,
    ) {}

    /**
     * The catalogs the package ships, parsed once per process.
     *
     * Memoized because the pre-scan sits in front of the single-file fast path:
     * re-reading and re-validating the artifact for every migration would put a
     * file read and a JSON decode into the inner loop of the run whose whole
     * promise is that it is not felt.
     */
    public static function bundled(): self
    {
        return self::$default ??= self::fromFile(
            dirname(__DIR__, 4).'/resources/data/'.self::ARTIFACT,
        );
    }

    /** Forget the memoized bundled catalogs — for tests that swap the artifact. */
    public static function forgetBundled(): void
    {
        self::$default = null;
    }

    public static function fromFile(string $path): self
    {
        $raw = @file_get_contents($path);

        if ($raw === false) {
            throw InvalidPreScanCatalog::unreadable($path);
        }

        return self::fromJson($raw, basename($path));
    }

    public static function fromJson(string $json, string $origin): self
    {
        try {
            $decoded = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw InvalidPreScanCatalog::unparsable($origin, $exception->getMessage());
        }

        if (! is_array($decoded)) {
            throw InvalidPreScanCatalog::notAnObject($origin);
        }

        return self::fromArray($decoded, $origin);
    }

    /**
     * @param  array<array-key, mixed>  $decoded
     */
    public static function fromArray(array $decoded, string $origin): self
    {
        $version = $decoded['schema_version'] ?? null;

        if ($version !== self::SCHEMA_VERSION) {
            throw InvalidPreScanCatalog::unsupportedSchemaVersion($origin, $version, self::SCHEMA_VERSION);
        }

        $catalogs = $decoded['catalogs'] ?? null;

        if (! is_array($catalogs) || $catalogs === []) {
            throw InvalidPreScanCatalog::malformedKey($origin, 'catalogs', 'a non-empty object of named catalogs');
        }

        $parsed = [];

        foreach ($catalogs as $name => $catalog) {
            $key = (string) $name;
            $parsed[$key] = self::parseCatalog($key, $catalog, $origin);
        }

        ksort($parsed);

        return new self($origin, self::SCHEMA_VERSION, $parsed);
    }

    /** The named catalog, or a named error listing what the artifact does carry. */
    public function catalog(string $name): PreScanCatalog
    {
        return $this->catalogs[$name] ?? throw InvalidPreScanCatalog::unknownCatalog(
            $this->origin,
            $name,
            implode(', ', $this->names()),
        );
    }

    /**
     * Every catalog name in the artifact, sorted — the enumeration the catalog
     * documentation and the completeness test consume.
     *
     * @return list<string>
     */
    public function names(): array
    {
        return array_keys($this->catalogs);
    }

    private static function parseCatalog(string $name, mixed $catalog, string $origin): PreScanCatalog
    {
        if (! is_array($catalog)) {
            throw InvalidPreScanCatalog::malformedKey($origin, "catalogs.{$name}", 'an object');
        }

        $description = $catalog['description'] ?? null;

        if (! is_string($description) || trim($description) === '') {
            throw InvalidPreScanCatalog::malformedKey($origin, "catalogs.{$name}.description", 'a non-empty string');
        }

        $entries = $catalog['entries'] ?? null;

        if (! is_array($entries) || $entries === []) {
            throw InvalidPreScanCatalog::malformedKey($origin, "catalogs.{$name}.entries", 'a non-empty list of entries');
        }

        $parsed = [];
        $seen = [];

        foreach (array_values($entries) as $index => $entry) {
            $parsed[] = $line = self::parseEntry($name, $index, $entry, $origin);

            if (in_array($line->target->raw, $seen, true)) {
                throw InvalidPreScanCatalog::duplicateTarget($origin, $name, $line->target->raw);
            }

            $seen[] = $line->target->raw;
        }

        return new PreScanCatalog($name, $description, $parsed);
    }

    private static function parseEntry(string $catalog, int $index, mixed $entry, string $origin): CatalogEntry
    {
        $path = "catalogs.{$catalog}.entries.{$index}";

        if (! is_array($entry)) {
            throw InvalidPreScanCatalog::malformedKey($origin, $path, 'an object with the keys: target, kind, reason');
        }

        return new CatalogEntry(
            CatalogTarget::parse(self::requiredString($entry, 'target', $path, $origin), $origin),
            self::requiredString($entry, 'kind', $path, $origin),
            self::requiredString($entry, 'reason', $path, $origin),
        );
    }

    /**
     * @param  array<array-key, mixed>  $entry
     */
    private static function requiredString(array $entry, string $key, string $path, string $origin): string
    {
        $value = $entry[$key] ?? null;

        if (! is_string($value) || trim($value) === '') {
            throw InvalidPreScanCatalog::malformedKey($origin, "{$path}.{$key}", 'a non-empty string');
        }

        return $value;
    }
}
