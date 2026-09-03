<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

/**
 * One pending migration handed TO a captor — file plus class, nothing more.
 *
 * This exists to make the captor's input contract explicit: a captor is given an
 * already-resolved, already-sorted list and resolves nothing itself. Passing a
 * bare array of paths would leave the class name to be re-derived inside every
 * captor, which is exactly the second resolution path this design forbids.
 *
 * The resolver enriches it with what a run and a report need — the repo-relative
 * path (deterministic across machines, and what a finding shows), the order index,
 * the prospective batch number, and the target connection. The captors read only
 * `file` and `migrationClass`, so those extra fields are optional and default to a
 * bare value a captor test can still construct.
 */
final readonly class PendingMigration
{
    public function __construct(
        public string $file,
        public string $migrationClass,
        public ?string $relativePath = null,
        public int $orderIndex = 0,
        public ?int $batchNumber = null,
        public ?string $connection = null,
    ) {}

    /**
     * The sort key that fixes run order: the migration file's basename, which
     * carries Laravel's timestamp prefix. Deterministic across machines because
     * it never involves a filesystem listing order.
     */
    public function sortKey(): string
    {
        return basename($this->file);
    }
}
