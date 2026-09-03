<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Migrations\Migrator;
use Pushery\SQLens\Contracts\PendingResolver;
use Throwable;

/**
 * Resolves which migrations are pending, in which order, for a connection — the
 * input to every lint run — by composing the answer from the Laravel migrator's
 * file discovery and the migration-repository table, without ever writing to it.
 *
 * The migrator has no public "which are pending" method, so this composes it the
 * way the migrator does internally: the migration files (discovered and sorted by
 * name, never by filesystem order) minus the migrations already recorded as run.
 * The order is therefore deterministic across machines, and the prospective batch
 * number is the next one the migrator would assign.
 *
 * Two promises are held here structurally:
 *
 *   - **It only reads.** Every query is a `SELECT` — the migration table's rows and
 *     its highest batch — and it takes no lock. It never records or removes a
 *     migration; that is the migrator's job under a real `migrate`, never a lint's.
 *   - **It reads the WRITE side.** On a read/write split the read replica can lag,
 *     so a migration just recorded might not show there yet and would be
 *     mis-reported as still pending. The repository reads therefore use the write
 *     PDO explicitly, so "pending" reflects the instance deployments target.
 *
 * And the dangerous shape is refused: an unreachable connection, a missing
 * migration table, or an empty migration path is a NAMED skip, never an empty list
 * read as "nothing pending, all clean".
 *
 * `Migrator::withoutMigrations()` (a harness feature that excludes specific
 * migrations from a run) is not honored here — it is set at migrate time by a test
 * harness, not something a lint sees, and its state is not publicly readable. A
 * migration a harness excluded would be reported as pending, which for a read-only
 * lint over-reports rather than misses.
 *
 * @param  list<string>  $migrationPaths
 */
final readonly class PendingMigrationResolver implements PendingResolver
{
    /**
     * @param  list<string>  $migrationPaths
     */
    public function __construct(
        private DatabaseManager $db,
        private Migrator $migrator,
        private array $migrationPaths,
        private string $migrationsTable,
        private string $projectRoot,
    ) {}

    public function resolve(string $connection): PendingResolution
    {
        if ($this->migrationPaths === []) {
            return PendingResolution::skipped(PendingSkipReason::EmptyMigrationPath);
        }

        $target = $this->db->connection($connection);

        // Reachability first: a connection that cannot be opened is a named skip, not
        // an empty pending list read as success.
        try {
            $target->getPdo();
        } catch (Throwable) {
            return PendingResolution::skipped(PendingSkipReason::ConnectionUnreachable);
        }

        // The migration repository must exist, or "which ran" is unknowable — a fresh
        // project is distinguished from a broken connection this way.
        if (! $target->getSchemaBuilder()->hasTable($this->migrationsTable)) {
            return PendingResolution::skipped(PendingSkipReason::NoMigrationTable);
        }

        // Files, discovered and sorted by migration name (never filesystem order).
        $files = $this->migrator->getMigrationFiles($this->migrationPaths);

        if ($files === []) {
            return PendingResolution::skipped(PendingSkipReason::EmptyMigrationPath);
        }

        // The already-run migrations and the last batch, read from the WRITE side so a
        // lagging replica cannot make a recorded migration look pending.
        $ran = [];

        foreach ($target->table($this->migrationsTable)->useWritePdo()->pluck('migration') as $migration) {
            if (is_string($migration)) {
                $ran[] = $migration;
            }
        }

        $maxBatch = $target->table($this->migrationsTable)->useWritePdo()->max('batch');
        $batch = (is_numeric($maxBatch) ? (int) $maxBatch : 0) + 1;

        $pending = array_diff_key($files, array_flip($ran));

        $migrations = [];
        $index = 0;

        foreach ($pending as $name => $path) {
            $migrations[] = new PendingMigration(
                file: $path,
                migrationClass: (string) $name,
                relativePath: $this->relativePath($path),
                orderIndex: $index,
                batchNumber: $batch,
                connection: $connection,
            );
            $index++;
        }

        return PendingResolution::resolved($migrations);
    }

    /** The repo-relative path — deterministic across machines, and what a finding shows. */
    private function relativePath(string $path): string
    {
        return str_replace(rtrim($this->projectRoot, '/').'/', '', $path);
    }
}
