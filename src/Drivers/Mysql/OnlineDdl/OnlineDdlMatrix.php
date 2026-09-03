<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\OnlineDdl;

use JsonException;
use Pushery\SQLens\Exceptions\InvalidRuleEvidence;

/**
 * Reads the bundled online-DDL matrix into typed {@see MatrixEntry} objects. Strictly
 * read-only: no database connection, no network, no writes — a lint run reads facts, it
 * does not touch a server.
 *
 * It follows the pattern the PostgreSQL type-change matrix loader established (that class is
 * not named here — the driver-isolation guard forbids the MySQL driver from reaching for a
 * PostgreSQL-driver name, even in a doc comment): the bundled data artifacts share the "a
 * shipped data file could not be read as written" contract ({@see InvalidRuleEvidence}), and
 * a malformed file is an ERROR, never an empty result that would quietly weaken every rule
 * that reads it. An UNKNOWN field is rejected, not ignored,
 * so a typo cannot smuggle a silently-dropped fact into a shipped artifact, and an entry
 * without a source is refused — provenance is enforced by the reader, not only the schema.
 */
final readonly class OnlineDdlMatrix
{
    /** The matrix format this reader implements; an unknown version is an error. */
    public const int SCHEMA_VERSION = 1;

    /** The one place the file path lives, so a later relocation is a single edit. */
    public const string BUNDLED_FILE = 'resources/data/online-ddl-matrix.json';

    /** @param  list<MatrixEntry>  $entries */
    private function __construct(
        public string $referenceServer,
        public string $about,
        public array $entries,
    ) {}

    /**
     * The bundled matrix, parsed once per process.
     *
     * The single-file fast path promises sub-second turnaround, and a rule that builds a resolver
     * per statement would otherwise re-read and re-parse this file every time — file I/O and a
     * JSON parse inside the loop, growing with the matrix. The facts are immutable and the shipped
     * file does not change while a process runs, so one parse is the whole truth.
     *
     * Only THIS accessor memoizes. {@see self::fromFile()} always reads, which is what the author
     * path (`composer matrix:normalize`) and every test loading a different file rely on — so the
     * cache can never hand back a stale copy of a file something just rewrote.
     *
     * The cache is a function-static rather than a class property because the class is readonly,
     * and a readonly class may not carry a static property with a default.
     */
    public static function bundled(): self
    {
        static $bundled = null;

        if (! $bundled instanceof self) {
            $bundled = self::fromFile(dirname(__DIR__, 4).'/'.self::BUNDLED_FILE);
        }

        return $bundled;
    }

    public static function fromFile(string $path): self
    {
        $raw = @file_get_contents($path);

        if ($raw === false) {
            throw InvalidRuleEvidence::unreadable($path);
        }

        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw InvalidRuleEvidence::unparsable($path, $exception->getMessage());
        }

        return self::fromArray($decoded, $path);
    }

    /** @param  array<string, mixed>  $data */
    public static function fromArray(array $data, string $origin): self
    {
        if (($data['schema_version'] ?? null) !== self::SCHEMA_VERSION) {
            throw InvalidRuleEvidence::unsupportedSchemaVersion($origin, $data['schema_version'] ?? null, self::SCHEMA_VERSION);
        }

        self::allowOnly($data, ['schema_version', 'reference_server', 'about', 'entries'], $origin, 'the matrix');

        $entries = [];
        $seen = [];

        foreach (self::listOf($data, 'entries', $origin) as $raw) {
            if (! is_array($raw)) {
                throw InvalidRuleEvidence::malformed($origin, 'entries', 'each entry an object');
            }

            /** @var array<string, mixed> $raw */
            $entry = self::entry($raw, $origin);

            if (isset($seen[$entry->id])) {
                throw InvalidRuleEvidence::malformed($origin, 'entries', "a unique id per entry — \"{$entry->id}\" appears more than once");
            }

            $seen[$entry->id] = true;
            $entries[] = $entry;
        }

        // A shipped facts file with no facts in it is a defect, not a legitimate state. Loaded
        // quietly it would answer every operation with "not classified" — an undetermined for
        // everything, which reads like a cautious tool rather than a missing file.
        if ($entries === []) {
            throw InvalidRuleEvidence::malformed($origin, 'entries', 'at least one entry — a matrix with none classifies nothing');
        }

        return new self(self::str($data, 'reference_server', $origin), self::str($data, 'about', $origin), $entries);
    }

    /** @return list<MatrixEntry> */
    public function all(): array
    {
        return $this->entries;
    }

    /** @param  array<string, mixed>  $data */
    private static function entry(array $data, string $origin): MatrixEntry
    {
        self::allowOnly(
            $data,
            ['id', 'operation', 'algorithm', 'rebuilds_table', 'permits_concurrent_dml', 'lock', 'min_version', 'max_version', 'conditions', 'sources', 'notes', 'stability'],
            $origin,
            'an entry',
        );

        $sources = self::sources($data, $origin);

        if ($sources === []) {
            throw InvalidRuleEvidence::malformed($origin, 'sources', 'at least one source per entry');
        }

        $algorithm = OnlineDdlAlgorithm::tryFrom(self::str($data, 'algorithm', $origin));

        if (! $algorithm instanceof OnlineDdlAlgorithm) {
            throw InvalidRuleEvidence::malformed($origin, 'algorithm', 'one of instant, inplace, copy, not_applicable');
        }

        $lock = LockImplication::tryFrom(self::str($data, 'lock', $origin));

        if (! $lock instanceof LockImplication) {
            throw InvalidRuleEvidence::malformed($origin, 'lock', 'one of none, shared, exclusive');
        }

        $stability = self::str($data, 'stability', $origin);

        if ($stability !== 'stable' && $stability !== 'preview') {
            throw InvalidRuleEvidence::malformed($origin, 'stability', 'either stable or preview');
        }

        return new MatrixEntry(
            id: self::str($data, 'id', $origin),
            operation: self::str($data, 'operation', $origin),
            algorithm: $algorithm,
            rebuildsTable: self::bool($data, 'rebuilds_table', $origin),
            permitsConcurrentDml: self::bool($data, 'permits_concurrent_dml', $origin),
            lock: $lock,
            minVersion: self::str($data, 'min_version', $origin),
            maxVersion: self::nullableStr($data, 'max_version', $origin),
            conditions: self::conditions($data, $origin),
            sources: $sources,
            notes: self::str($data, 'notes', $origin),
            stability: $stability,
        );
    }

    /**
     * @param  array<string, mixed>  $data
     * @return list<MatrixCondition>
     */
    private static function conditions(array $data, string $origin): array
    {
        $conditions = [];

        foreach (self::listOf($data, 'conditions', $origin) as $raw) {
            if (! is_array($raw)) {
                throw InvalidRuleEvidence::malformed($origin, 'conditions', 'each condition an object');
            }

            /** @var array<string, mixed> $raw */
            self::allowOnly($raw, ['id', 'text'], $origin, 'a condition');
            $conditions[] = new MatrixCondition(self::str($raw, 'id', $origin), self::str($raw, 'text', $origin));
        }

        return $conditions;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return list<MatrixSource>
     */
    private static function sources(array $data, string $origin): array
    {
        $sources = [];

        foreach (self::listOf($data, 'sources', $origin) as $raw) {
            if (! is_array($raw)) {
                throw InvalidRuleEvidence::malformed($origin, 'sources', 'each source an object');
            }

            /** @var array<string, mixed> $raw */
            self::allowOnly($raw, ['url', 'anchor', 'retrieved'], $origin, 'a source');
            $sources[] = new MatrixSource(self::str($raw, 'url', $origin), self::str($raw, 'anchor', $origin), self::str($raw, 'retrieved', $origin));
        }

        return $sources;
    }

    /**
     * @param  array<string, mixed>  $data
     * @param  list<string>  $allowed
     */
    private static function allowOnly(array $data, array $allowed, string $origin, string $what): void
    {
        foreach (array_keys($data) as $key) {
            if (! in_array($key, $allowed, true)) {
                throw InvalidRuleEvidence::malformed($origin, (string) $key, "not a known field of {$what}");
            }
        }
    }

    /** @param  array<string, mixed>  $data */
    private static function str(array $data, string $key, string $origin): string
    {
        $value = $data[$key] ?? null;

        if (! is_string($value) || $value === '') {
            throw InvalidRuleEvidence::malformed($origin, $key, 'a non-empty string');
        }

        return $value;
    }

    /** @param  array<string, mixed>  $data */
    private static function nullableStr(array $data, string $key, string $origin): ?string
    {
        if (($data[$key] ?? null) === null) {
            return null;
        }

        return self::str($data, $key, $origin);
    }

    /** @param  array<string, mixed>  $data */
    private static function bool(array $data, string $key, string $origin): bool
    {
        $value = $data[$key] ?? null;

        if (! is_bool($value)) {
            throw InvalidRuleEvidence::malformed($origin, $key, 'a boolean');
        }

        return $value;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return list<mixed>
     */
    private static function listOf(array $data, string $key, string $origin): array
    {
        $value = $data[$key] ?? null;

        if (! is_array($value)) {
            throw InvalidRuleEvidence::malformed($origin, $key, 'a list');
        }

        return array_values($value);
    }
}
