<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Capture\PendingResolution;

/**
 * Answers "which migrations are pending, in which order" for a connection — the
 * input to every lint run.
 *
 * It is a seam so the resolution can be tested with a fake against no database, and
 * so the one rule about it is enforceable in one place: it READS only. It never
 * writes to the migration repository and never takes a lock; a connection it cannot
 * reach is a named skip, never an empty list. The concrete resolver composes the
 * answer from the Laravel migrator's repository, addressing the write side of a
 * read/write split.
 */
interface PendingResolver
{
    /**
     * Resolve the pending migrations for the named connection, or a named skip when
     * the pending set cannot be determined.
     */
    public function resolve(string $connection): PendingResolution;
}
