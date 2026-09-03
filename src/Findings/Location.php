<?php

declare(strict_types=1);

namespace Pushery\SQLens\Findings;

use Pushery\SQLens\Subjects\MigrationDirection;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * One location type that addresses a migration file, a catalog object and a PHP
 * callsite alike, so console, JSON, GitHub annotations and SARIF all consume the
 * same structure.
 *
 * The location is STRUCTURED (named constructors + a deterministic sort key), not
 * embedded in a message string. Its presence as its own `location` key in the
 * array projection is what the serialization contract relies on.
 *
 * Two determinism rules are enforced here, because they are the classic breakage
 * points: file paths are stored relative to the project root (an absolute path
 * would differ between a dev Mac and CI), and the sort key is stable across runs.
 * A catalog location NEVER carries a DSN or password — only the connection name;
 * naming which instance was audited is a deliberate statement (read/write split).
 */
final readonly class Location
{
    private function __construct(
        public LocationKind $kind,
        public ?string $file = null,
        public ?int $line = null,
        public ?string $migrationClass = null,
        public ?int $statementIndex = null,
        public ?MigrationDirection $direction = null,
        public ?string $driver = null,
        public ?string $instance = null,
        public ?string $objectName = null,
        public ?SchemaObjectType $objectType = null,
        public ?string $method = null,
    ) {}

    public static function inMigration(
        string $file,
        string $migrationClass,
        int $statementIndex,
        MigrationDirection $direction,
        string $projectRoot,
        ?int $line = null,
        // The schema object the finding is about, when the rule named one. A migration location
        // says WHERE the statement is; these say WHAT it is about, and the two are different
        // questions — the file tells a reader which line to open, the object tells a later run
        // whether it is looking at the same thing. Optional because almost no rule names one.
        ?string $objectName = null,
        ?SchemaObjectType $objectType = null,
    ): self {
        return new self(
            kind: LocationKind::Migration,
            file: self::relativize($file, $projectRoot),
            line: $line,
            migrationClass: $migrationClass,
            statementIndex: $statementIndex,
            direction: $direction,
            objectName: $objectName,
            objectType: $objectType,
        );
    }

    /**
     * A catalog location always names the addressed instance — which instance was
     * audited is a statement, never optional. The instance is a connection name,
     * never a DSN or password.
     */
    public static function inCatalog(
        string $driver,
        string $instance,
        string $objectName,
        SchemaObjectType $objectType,
    ): self {
        return new self(
            kind: LocationKind::Catalog,
            driver: $driver,
            instance: $instance,
            objectName: $objectName,
            objectType: $objectType,
        );
    }

    public static function inCallsite(
        string $file,
        int $line,
        string $method,
        string $projectRoot,
    ): self {
        return new self(
            kind: LocationKind::Callsite,
            file: self::relativize($file, $projectRoot),
            line: $line,
            method: $method,
        );
    }

    /**
     * A deterministic ordering key. Same state ⇒ same key, so findings sort
     * reproducibly here and stay stable in the baseline. Fixed-width padding on
     * the numeric parts keeps line 2 below line 10.
     */
    public function sortKey(): string
    {
        return match ($this->kind) {
            LocationKind::Migration => sprintf(
                'migration|%s|%s|%010d|%010d',
                $this->file ?? '',
                $this->direction instanceof MigrationDirection ? $this->direction->value : '',
                $this->statementIndex ?? 0,
                $this->line ?? 0,
            ),
            LocationKind::Catalog => sprintf(
                'catalog|%s|%s|%s|%s',
                $this->driver ?? '',
                $this->instance ?? '',
                $this->objectType instanceof SchemaObjectType ? $this->objectType->value : '',
                $this->objectName ?? '',
            ),
            LocationKind::Callsite => sprintf(
                'callsite|%s|%010d|%s',
                $this->file ?? '',
                $this->line ?? 0,
                $this->method ?? '',
            ),
        };
    }

    /**
     * A deterministic array projection with a fixed key order. Absent optional
     * fields are omitted rather than serialized as null, so the shape is stable
     * and free of null noise. Its presence as the finding's own `location` key is
     * what the serialization contract relies on.
     *
     * @return array<string, string|int>
     */
    public function toArray(): array
    {
        $projection = match ($this->kind) {
            LocationKind::Migration => [
                'kind' => $this->kind->value,
                'file' => $this->file,
                'line' => $this->line,
                'migration_class' => $this->migrationClass,
                'statement_index' => $this->statementIndex,
                'direction' => $this->direction instanceof MigrationDirection ? $this->direction->value : null,
                // Present even when null, and always both — the same discipline the catalog
                // branch above already follows. A projection whose KEYS depend on its content is
                // one every consumer has to defend against, and the one that forgets reads a
                // missing key as an absent object rather than as a rule that named none.
                'object_type' => $this->objectType instanceof SchemaObjectType ? $this->objectType->value : null,
                'object_name' => $this->objectName,
            ],
            LocationKind::Catalog => [
                'kind' => $this->kind->value,
                'driver' => $this->driver,
                'instance' => $this->instance,
                'object_type' => $this->objectType instanceof SchemaObjectType ? $this->objectType->value : null,
                'object_name' => $this->objectName,
            ],
            LocationKind::Callsite => [
                'kind' => $this->kind->value,
                'file' => $this->file,
                'line' => $this->line,
                'method' => $this->method,
            ],
        };

        return array_filter($projection, static fn (string|int|null $value): bool => $value !== null);
    }

    /**
     * Strip a leading project root so the stored path is relative. Pure string
     * work — no Foundation base_path(), so the fast path stays connection-free.
     */
    private static function relativize(string $path, string $projectRoot): string
    {
        $root = rtrim($projectRoot, '/').'/';

        return str_starts_with($path, $root)
            ? substr($path, strlen($root))
            : ltrim($path, '/');
    }
}
