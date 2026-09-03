<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql;

use JsonException;
use Pushery\SQLens\Exceptions\InvalidRuleEvidence;

/**
 * Classifies an `ALTER COLUMN … TYPE <target>` by its TARGET type, read from the
 * bundled `pg-type-change-matrix.json`. The source type is not in the migration SQL, so
 * this is deliberately a heuristic keyed on the target — the rule that consumes it
 * declares `confidence=heuristic`, and a target the matrix does not list is returned as
 * {@see TypeChangeImpact::Unknown} rather than guessed safe.
 *
 * Aliases fold to their canonical PostgreSQL spelling before lookup, and a length or
 * precision specifier is stripped, so `int8`, `integer`, and `NUMERIC(10, 2)` all
 * resolve the way the same change written by hand would.
 *
 * A malformed matrix is an error, not an empty result — read leniently, a typo would
 * turn every rewrite into an "unknown" and quietly weaken the rule. It reuses
 * {@see InvalidRuleEvidence} for its failure type: the two bundled data files share the
 * same "a shipped data artifact could not be read as written" contract.
 */
final readonly class PgTypeChangeMatrix
{
    /** The matrix format this reader implements; an unknown version is an error. */
    public const int SCHEMA_VERSION = 1;

    /**
     * @param  list<string>  $rewrite  canonical target types that force a rewrite
     * @param  list<string>  $metadataOnly  canonical target types that are catalog-only
     * @param  list<string>  $narrowing  canonical target types whose dominant case is a narrowing
     * @param  array<string, string>  $aliases  spelling → canonical target type
     */
    private function __construct(
        private array $rewrite,
        private array $metadataOnly,
        private array $narrowing,
        private array $aliases,
    ) {}

    public static function bundled(): self
    {
        return self::fromFile(dirname(__DIR__, 3).'/resources/data/pg-type-change-matrix.json');
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

        return new self(
            self::stringList($data['rewrite'] ?? null, $origin, 'rewrite'),
            self::stringList($data['metadata_only'] ?? null, $origin, 'metadata_only'),
            self::stringList($data['narrowing'] ?? null, $origin, 'narrowing'),
            self::stringMap($data['aliases'] ?? null, $origin),
        );
    }

    /**
     * The impact of changing a column to the given raw target type. A USING clause
     * forces a rewrite regardless and is decided by the caller, not here.
     */
    public function classify(string $rawTargetType): TypeChangeImpact
    {
        $type = $this->canonicalize($rawTargetType);

        if (in_array($type, $this->rewrite, true)) {
            return TypeChangeImpact::Rewrite;
        }

        if (in_array($type, $this->metadataOnly, true)) {
            return TypeChangeImpact::MetadataOnly;
        }

        return TypeChangeImpact::Unknown;
    }

    /**
     * Whether the target type's dominant real case is a NARROWING — a shrink of range or
     * precision that can truncate data and break an old app version writing wider values.
     * This is orthogonal to {@see classify()}: `integer` both rewrites AND narrows, on two
     * different axes. It is only true for the target types whose ONE common source is a
     * wider sibling (`integer`, `smallint`, `real`); a parametrized type like `varchar(50)`
     * cannot be told from a widening by the target alone and is deliberately not listed, so
     * this returns false for it.
     */
    public function isNarrowing(string $rawTargetType): bool
    {
        return in_array($this->canonicalize($rawTargetType), $this->narrowing, true);
    }

    /** Lowercased, length/precision stripped, alias folded — the form the matrix is keyed on. */
    private function canonicalize(string $rawTargetType): string
    {
        $type = strtolower(trim($rawTargetType));
        // Drop a "(255)" or "(10, 2)" specifier — the length does not change WHICH type
        // it is, and the matrix classifies by type, not width.
        $type = trim((string) preg_replace('/\s*\([^)]*\)/', '', $type));
        // Collapse the internal whitespace of a multi-word type ("timestamp  with …").
        $type = (string) preg_replace('/\s+/', ' ', $type);

        return $this->aliases[$type] ?? $type;
    }

    /**
     * @return list<string>
     */
    private static function stringList(mixed $value, string $origin, string $field): array
    {
        if (! is_array($value)) {
            throw InvalidRuleEvidence::malformed($origin, $field, 'a list of type names');
        }

        $list = [];

        foreach ($value as $entry) {
            if (! is_string($entry)) {
                throw InvalidRuleEvidence::malformed($origin, $field, 'type names as strings');
            }

            $list[] = $entry;
        }

        return $list;
    }

    /**
     * @return array<string, string>
     */
    private static function stringMap(mixed $value, string $origin): array
    {
        if (! is_array($value)) {
            throw InvalidRuleEvidence::malformed($origin, 'aliases', 'a map of spelling to canonical type');
        }

        $map = [];

        foreach ($value as $key => $entry) {
            if (! is_string($key) || ! is_string($entry)) {
                throw InvalidRuleEvidence::malformed($origin, 'aliases', 'string keys and string values');
            }

            $map[$key] = $entry;
        }

        return $map;
    }
}
