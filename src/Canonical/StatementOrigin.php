<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

use Pushery\SQLens\Subjects\MigrationDirection;
use Pushery\SQLens\Subjects\MigrationSql;

/**
 * Where a statement came from — the migration file, class, statement index and
 * direction. Raw SQL is visible ONLY as provenance, never as a working surface:
 * once a statement is canonical, rules read the canonical form, and the origin is
 * how a finding points back at the source without regexing grammar internals.
 */
final readonly class StatementOrigin
{
    public function __construct(
        public string $file,
        public string $migrationClass,
        public int $statementIndex,
        public MigrationDirection $direction,
    ) {}

    /** Lift the origin off a captured migration-SQL subject. */
    public static function fromSubject(MigrationSql $subject): self
    {
        return new self(
            file: $subject->sourceFile,
            migrationClass: $subject->migrationClass,
            statementIndex: $subject->statementIndex,
            direction: $subject->direction,
        );
    }
}
