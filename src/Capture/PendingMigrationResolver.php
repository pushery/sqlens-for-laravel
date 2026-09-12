<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Migrations\Migrator;
use Pushery\SQLens\Contracts\PendingResolver;
use Pushery\SQLens\Security\PathBinding;
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
     * @param  bool  $includeVendorMigrations  whether a migration discovered inside `vendor/` is
     *                                         enumerated. False drops it before anything reads it;
     *                                         see {@see self::vendorFiltered()} for what is never
     *                                         dropped and why.
     */
    public function __construct(
        private DatabaseManager $db,
        private Migrator $migrator,
        private array $migrationPaths,
        private string $migrationsTable,
        private string $projectRoot,
        private bool $includeVendorMigrations = true,
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

        $outstanding = array_diff_key($files, array_flip($ran));
        $pending = $this->vendorFiltered($outstanding);

        // Something was waiting to run, and every one of those migrations was a package's. That is
        // a different fact from "nothing is pending", and it gets its own skip rather than an empty
        // list: the run really did find migrations to judge and really is not judging them, and a
        // reader told that nothing was read would stop looking while a package's migration waits.
        //
        // The question is asked of the pending set, not of the files on disk. An application's own
        // migrations have normally all run, so "was every discovered file a package's" is answered
        // no by files that will never run again, and the skip was only reached by an application
        // with no migrations of its own.
        if ($outstanding !== [] && $pending === []) {
            return PendingResolution::skipped(PendingSkipReason::OnlyVendorMigrations);
        }

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

    /**
     * The discovered files, less the ones that live inside the dependency tree.
     *
     * ## Why the enumeration filters at all, when the classifier already knew
     *
     * The capture layer has always known a `vendor/` migration from one of yours — that is what
     * {@see PathBinding} decides, and what
     * `security.include_vendor_migrations` switches. But it decides it about a statement that has
     * ALREADY been captured, so a package's migration was still loaded, still pretend-executed, and
     * still able to produce a capture-layer finding of its own. A first run after `composer require`
     * therefore failed on three findings inside another package, none of which the project could
     * fix, every one of them repeating on every run.
     *
     * The switch's own docblock makes the argument, and it holds here just as well: a rule whose
     * only available fix is "open an issue upstream" is one people silence wholesale, taking the
     * findings they COULD have acted on with it. It weighs more for `lint`, the suite that hangs in
     * CI, where the gate would be red on day one over another package's migrations.
     *
     * ## What is deliberately NOT filtered
     *
     * A path somebody NAMED. `--path`, `sqlens.migration_paths` and `--file` are a person saying
     * "these", and quietly dropping part of what they named would make the argument advisory. The
     * caller decides that and it arrives here as `$includeVendorMigrations`.
     *
     * `sqlens:predeploy` passes true as well, and that one is not a preference: a package's
     * migration RUNS during a deploy and can take an ACCESS EXCLUSIVE lock like any other. Hiding it
     * from the run that exists to see what the deploy is about to walk into would answer that
     * question wrongly.
     *
     * @param  array<string, string>  $files
     * @return array<string, string>
     */
    private function vendorFiltered(array $files): array
    {
        if ($this->includeVendorMigrations) {
            return $files;
        }

        // Through `VendorPath`, which RESOLVES before it matches. Matching the raw path here would
        // disagree with the capture layer under a Composer `path` repository — the raw path still
        // carries `/vendor/` where the resolved one does not — and the file would then be dropped
        // from the enumeration while the classifier bound it as a migration of yours.
        return array_filter($files, static fn (string $path): bool => ! VendorPath::contains($path));
    }

    /** The repo-relative path — deterministic across machines, and what a finding shows. */
    private function relativePath(string $path): string
    {
        return str_replace(rtrim($this->projectRoot, '/').'/', '', $path);
    }
}
