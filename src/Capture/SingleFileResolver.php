<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Illuminate\Database\Migrations\Migrator;

/**
 * The `--file` fast-path subject source: it resolves exactly ONE migration file to a
 * subject, the sibling of the pending resolver. It is the only new thing the fast
 * path adds — capture, canonicalization, rule selection, gates and the reporter stay
 * the full run's, so there is no second engine to drift (pitfall 13).
 *
 * It never opens a database connection: it resolves a path, checks the file, and
 * builds one subject. The migration is not run here — the captor does that under
 * pretend, which builds its grammar from the connection object without connecting,
 * so a pre-commit hook touches nothing a developer's machine does not already read.
 *
 * A path is refused unless it lands inside a configured migration path: `--file` is
 * a migration linter, not a general-purpose file linter, so it can never be pointed
 * at an arbitrary file on disk.
 */
final readonly class SingleFileResolver
{
    /** @param  list<string>  $migrationPaths  the configured migration paths a file must live under */
    public function __construct(
        private Migrator $migrator,
        private array $migrationPaths,
        private string $projectRoot,
    ) {}

    public function resolve(string $file, string $connection): PendingMigration|SingleFileFailure
    {
        $real = realpath($this->absolutePath($file));

        if ($real === false || ! is_file($real)) {
            return SingleFileFailure::NotFound;
        }

        if (! str_ends_with(strtolower($real), '.php')) {
            return SingleFileFailure::NotPhp;
        }

        if (! $this->withinMigrationPaths($real)) {
            return SingleFileFailure::OutsideMigrationPaths;
        }

        return new PendingMigration(
            file: $real,
            migrationClass: $this->migrator->getMigrationName($real),
            relativePath: $this->relativePath($real),
            orderIndex: 0,
            batchNumber: 1,
            connection: $connection,
        );
    }

    /** An absolute path stays; a relative one resolves against the project root. */
    private function absolutePath(string $file): string
    {
        if (str_starts_with($file, '/') || preg_match('#^[A-Za-z]:[\\\\/]#', $file) === 1) {
            return $file;
        }

        return rtrim($this->projectRoot, '/').'/'.ltrim($file, '/');
    }

    /** Whether the resolved file lives under a configured migration path. */
    private function withinMigrationPaths(string $real): bool
    {
        foreach ($this->migrationPaths as $path) {
            $base = realpath($path);

            if ($base !== false && str_starts_with($real, rtrim($base, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR)) {
                return true;
            }
        }

        return false;
    }

    /** The repo-relative path — deterministic across machines, and what a finding shows. */
    private function relativePath(string $path): string
    {
        return str_replace(rtrim($this->projectRoot, '/').'/', '', $path);
    }
}
