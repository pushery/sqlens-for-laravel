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
 * precision specifier is stripped, so `int8` and `integer` resolve the way the same change
 * written by hand would. A `numeric` that carries a precision is the exception: its
 * specifier decides the answer, so it is not classified by the type alone.
 *
 * Where the source is known after all, because an earlier migration of the same run gave the
 * column its type, {@see classifyFrom()} reads the pair.
 *
 * A malformed matrix is an error, not an empty result — read leniently, a typo would
 * turn every rewrite into an "unknown" and quietly weaken the rule. It reuses
 * {@see InvalidRuleEvidence} for its failure type: the two bundled data files share the
 * same "a shipped data artifact could not be read as written" contract.
 */
final readonly class PgTypeChangeMatrix
{
    /**
     * The canonical target types whose specifier decides the answer when it is written.
     *
     * @var list<string>
     */
    private const array DECIDED_BY_THEIR_SPECIFIER = ['numeric', 'timestamp', 'timestamp with time zone', 'time', 'time with time zone'];

    /**
     * The types whose every value fits a bigger size of the same type, or the type written without
     * one, so PostgreSQL relabels the column without reading it. A smaller size, or a `numeric` with
     * another scale, rewrites the table. Any other type written with another size is unknown: `char`
     * bare is `char(1)` and is padded anew, `float(24)` is `real` and `float(53)` is
     * `double precision`.
     *
     * Measured on 18.4 for the rewrite rule: `varchar(10)` to `varchar(20)`, `numeric(8,2)` to
     * `numeric(12,2)` and `timestamp(3)` to `timestamp(6)` kept the heap, `numeric(14,2)` to
     * `numeric(14,4)` and `timestamp(6)` to `timestamp(0)` rewrote it.
     *
     * @var list<string>
     */
    private const array GROW_IN_PLACE = ['varchar', 'numeric', 'timestamp', 'timestamp with time zone', 'time', 'time with time zone'];

    /**
     * Pairs of two types PostgreSQL converts without a cast function, the old one binary-coercible to
     * the new, so the change rewrites no row. `text` to a bare `varchar` is one more, decided where
     * the target's size can be read.
     *
     * @var list<array{string, string}>
     */
    private const array BINARY_COERCIBLE = [['varchar', 'text'], ['cidr', 'inet']];

    /**
     * The two types between which the session's time zone decides whether a change rewrites: since
     * PostgreSQL 12 it is metadata-only under UTC and a rewrite otherwise. Public so the rule that
     * hands the reader that condition keys it on this list rather than on a copy of it.
     *
     * @var list<string>
     */
    public const array DECIDED_BY_THE_SESSION = ['timestamp', 'timestamp with time zone'];

    /**
     * The character types. A value of a type this matrix lists under `rewrite` becomes one of them
     * only through that type's output function, row by row, so such a change rewrites the table.
     *
     * @var list<string>
     */
    private const array CHARACTER_TYPES = ['text', 'varchar', 'char'];

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

        // A `numeric` target carries its precision and scale, and they decide the answer on their
        // own: raising the precision at the same scale keeps every stored value and rewrites nothing,
        // changing the scale rewrites the table, and the column's current pair is not in the
        // statement. Measured on 18.4: `numeric(8,2)` to `numeric(12,2)` kept the heap, and
        // `numeric(14,2)` to `numeric(14,4)` rewrote it. A time type carries its precision the same
        // way: `timestamp(3)` to `timestamp(6)` kept the heap, `timestamp(6)` to `timestamp(0)`
        // rewrote it, and `time` and `timestamptz` behaved alike. A bare target stays keyed on its
        // dominant case, a change from another type.
        if (in_array($type, self::DECIDED_BY_THEIR_SPECIFIER, true) && str_contains($rawTargetType, '(')) {
            return TypeChangeImpact::Unknown;
        }

        if (in_array($type, $this->rewrite, true)) {
            return TypeChangeImpact::Rewrite;
        }

        if (in_array($type, $this->metadataOnly, true)) {
            return TypeChangeImpact::MetadataOnly;
        }

        return TypeChangeImpact::Unknown;
    }

    /**
     * The impact of changing a column from a type the run knows to the given raw target type.
     *
     * {@see classify()} answers from the target alone, which is all a statement names. Where an
     * earlier migration of the run gave the column its type, the pair decides: restating the type a
     * column has rewrites nothing, neither does a change PostgreSQL makes without a cast function or
     * a bigger size of a type that grows in place, and any other change to a type this matrix
     * rewrites to rewrites the table.
     */
    public function classifyFrom(string $rawSourceType, string $rawTargetType): TypeChangeImpact
    {
        $source = $this->canonicalize($rawSourceType);
        $target = $this->canonicalize($rawTargetType);

        if ($source === $target) {
            return $this->resized($target, $this->specifier($rawSourceType), $this->specifier($rawTargetType));
        }

        if (in_array([$source, $target], self::BINARY_COERCIBLE, true)
            || ($source === 'text' && $target === 'varchar' && $this->specifier($rawTargetType) === null)) {
            return TypeChangeImpact::MetadataOnly;
        }

        // Between the two timestamp types the session decides, and the source adds nothing to what
        // the target alone says about that.
        if (in_array($source, self::DECIDED_BY_THE_SESSION, true) && in_array($target, self::DECIDED_BY_THE_SESSION, true)) {
            return $this->classify($rawTargetType);
        }

        if (in_array($target, $this->rewrite, true)
            || (in_array($target, self::CHARACTER_TYPES, true) && in_array($source, $this->rewrite, true))) {
            return TypeChangeImpact::Rewrite;
        }

        return TypeChangeImpact::Unknown;
    }

    /** The impact of keeping a column's type and writing its size anew, from one size to another or to none. */
    private function resized(string $type, ?string $from, ?string $to): TypeChangeImpact
    {
        if ($from === $to) {
            return TypeChangeImpact::MetadataOnly;
        }

        if (! in_array($type, self::GROW_IN_PLACE, true)) {
            return TypeChangeImpact::Unknown;
        }

        if ($to === null) {
            return TypeChangeImpact::MetadataOnly;
        }

        if ($from === null) {
            return TypeChangeImpact::Unknown;
        }

        [$fromSize, $fromScale] = $this->sizeOf($from);
        [$toSize, $toScale] = $this->sizeOf($to);

        return $toSize >= $fromSize && $toScale === $fromScale ? TypeChangeImpact::MetadataOnly : TypeChangeImpact::Rewrite;
    }

    /**
     * Whether the target type's dominant real case is a NARROWING — a shrink of range or
     * precision that can truncate data and break an old app version writing wider values.
     * This is orthogonal to {@see classify()}: `integer` both rewrites AND narrows, on two
     * different axes. It is only true for the target types whose one common source is a
     * wider sibling (`integer`, `smallint`, `real`); a parametrized type like `varchar(50)`
     * cannot be told from a widening by the target alone and is deliberately not listed, so
     * this returns false for it.
     */
    public function isNarrowing(string $rawTargetType): bool
    {
        return in_array($this->canonicalize($rawTargetType), $this->narrowing, true);
    }

    /**
     * The canonical name of a written target type, for a caller that must key on the same value
     * this matrix keys on.
     *
     * Public so a rule can look up a per-target caveat without normalizing the type a second time.
     * A second normalization is a second truth: it would agree with this one until somebody adds an
     * alias, and then the caveat would silently stop matching the classification it belongs to.
     */
    public function canonicalTarget(string $rawTargetType): string
    {
        return $this->canonicalize($rawTargetType);
    }

    /** Lowercased, length/precision stripped, alias folded — the form the matrix is keyed on. */
    private function canonicalize(string $rawTargetType): string
    {
        $type = strtolower(trim($rawTargetType));
        // Drop a "(255)" or "(10, 2)" specifier — the length does not change which type
        // it is, and the matrix classifies by type, not width.
        $type = trim((string) preg_replace('/\s*\([^)]*\)/', '', $type));
        // Collapse the internal whitespace of a multi-word type ("timestamp  with …").
        $type = (string) preg_replace('/\s+/', ' ', $type);

        return $this->aliases[$type] ?? $type;
    }

    /** The parenthesized length or precision a written type carries, without its spaces, or null. */
    private function specifier(string $rawType): ?string
    {
        return preg_match('/\([^)]*\)/', $rawType, $matches) === 1 ? (string) preg_replace('/\s+/', '', $matches[0]) : null;
    }

    /**
     * A size as its two numbers, the scale 0 where only one is written.
     *
     * @return array{int, int}
     */
    private function sizeOf(string $specifier): array
    {
        $numbers = array_map(intval(...), explode(',', trim($specifier, '()')));

        return [$numbers[0], $numbers[1] ?? 0];
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
