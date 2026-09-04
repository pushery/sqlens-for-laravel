<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security;

use Pushery\SQLens\Capture\VendorPath;

/**
 * Decides whether a captured statement came from a migration — the mechanism behind "a password
 * literal is Critical in a migration and nothing at all in a seeder".
 *
 * ## Why the registration decides, and never the file name
 *
 * The tempting implementation matches `*_seeder.php` or looks for `database/migrations` in the
 * string. Both are guesses, and both are wrong in ordinary projects:
 *
 * - A package registers its own migrations through `loadMigrationsFrom()`, at a path that is
 *   usually `vendor/<vendor>/<package>/database/migrations` and can be anything at all. Those ARE
 *   migrations, and a name check would file them as seeders.
 * - A tenant setup nests migrations in `database/migrations/tenant/`. A path check comparing for
 *   equality misses it; one comparing prefixes does not, which is why this class compares prefixes.
 * - A seeder is free to be called `2026_01_01_000000_seed_users.php`. Nothing stops it, and the
 *   name check would call it a migration.
 *
 * So the migrator's own registered paths are the truth, and they arrive as a constructor argument
 * rather than being read here: the lint layer already resolves them once — `databasePath('migrations')`
 * plus `Migrator::paths()` — and a second resolution would be a second answer that can disagree.
 *
 * ## Why `vendor/` is excluded by default, and why it is a switch rather than an assumption
 *
 * A package's migrations are code the team did not write and usually cannot change. Reporting a
 * Critical there hands somebody a finding whose only available fix is "open an issue upstream",
 * repeated on every run, and a rule that cannot be acted on is a rule that gets silenced wholesale —
 * taking the findings that COULD be acted on with it.
 *
 * It is a switch and not a hard rule because the opposite case is real: an audit that has to state
 * what the whole dependency tree does needs to see them. `sqlens.security.include_vendor_migrations`
 * turns them back on, and the default is stated in config rather than buried here.
 *
 * ## Determinism
 *
 * Every comparison happens on a resolved absolute path, and what a finding CARRIES is the
 * repo-relative one. A dev Mac and a CI container disagree about the absolute prefix and agree about
 * everything after it, so the finding text is identical on both — which is what lets a baseline
 * written on one machine match on the other.
 */
final readonly class PathBinding
{
    /**
     * @param  list<string>  $migrationPaths  the registered migration paths, resolved once by the caller
     * @param  string  $projectRoot  the repository root, for the relative path a finding shows
     * @param  bool  $includeVendorMigrations  whether a migration under `vendor/` counts as one
     */
    public function __construct(
        private array $migrationPaths,
        private string $projectRoot,
        private bool $includeVendorMigrations = false,
    ) {}

    /**
     * The binding for one source file, or {@see OriginBinding::Unknown} when there is no file.
     *
     * `null` and the empty string are the fast path's answer: `sqlens:lint --file` can be pointed at
     * a snippet, and a statement that reached the run without provenance genuinely has none. That is
     * a different fact from "it is not a migration", and the enum keeps them apart.
     */
    public function for(?string $sourceFile): OriginBinding
    {
        if ($sourceFile === null || trim($sourceFile) === '') {
            return OriginBinding::Unknown;
        }

        $resolved = $this->resolve($sourceFile);

        // A path that does not exist on disk is UNKNOWN rather than not-a-migration. The two cases
        // it covers are a file that was deleted between capture and judgment, and a synthetic
        // subject built by a test or a tool — and calling either of them "not a migration" would
        // silence a path-bound rule on evidence nobody has.
        if ($resolved === null) {
            return OriginBinding::Unknown;
        }

        if (! $this->includeVendorMigrations && $this->withinVendor($resolved)) {
            return OriginBinding::NotAMigration;
        }

        return $this->withinRegisteredPath($resolved)
            ? OriginBinding::Migration
            : OriginBinding::NotAMigration;
    }

    /**
     * The repo-relative form of a path — what a finding shows, and the reason two machines agree.
     *
     * Left as-is when the path does not sit under the project root: a truncated absolute path would
     * read like a relative one and send somebody looking in the wrong place.
     */
    public function relative(string $path): string
    {
        $root = rtrim($this->projectRoot, '/\\').DIRECTORY_SEPARATOR;

        return str_starts_with($path, $root) ? substr($path, strlen($root)) : $path;
    }

    /** The absolute, symlink-resolved path, or null when it does not exist. */
    private function resolve(string $sourceFile): ?string
    {
        $absolute = $this->absolute($sourceFile);
        $real = realpath($absolute);

        return $real === false ? null : $real;
    }

    /** An absolute path stays; a relative one resolves against the project root. */
    private function absolute(string $path): string
    {
        if (str_starts_with($path, '/') || preg_match('#^[A-Za-z]:[\\\\/]#', $path) === 1) {
            return $path;
        }

        return rtrim($this->projectRoot, '/\\').DIRECTORY_SEPARATOR.ltrim($path, '/\\');
    }

    /**
     * Whether the file sits under one of the registered paths.
     *
     * Compared as a PREFIX with the separator appended, which is doing two jobs. It admits a
     * subdirectory — `database/migrations/tenant/…` is under `database/migrations` — and it refuses
     * a sibling whose name merely starts the same way: without the trailing separator,
     * `database/migrations_archive` would match `database/migrations` and an archived migration
     * would be judged as a live one.
     */
    private function withinRegisteredPath(string $resolved): bool
    {
        foreach ($this->migrationPaths as $path) {
            $base = realpath($path);

            if ($base === false) {
                continue;
            }

            if (str_starts_with($resolved, rtrim($base, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the file lives inside the dependency tree.
     *
     * Delegated to {@see VendorPath}, which the lint layer asks the same question. It used to be
     * two segment matches — this one and the enumeration's — and that is the shape this package has
     * been bitten by before: each side internally consistent, neither aware the other exists.
     * {@see VendorPath} carries the measurement of how they diverge under a Composer `path`
     * repository.
     *
     * The path arriving here is already resolved, and passing it through the resolution again is
     * harmless: `realpath()` of a resolved path is that path.
     */
    private function withinVendor(string $resolved): bool
    {
        return VendorPath::contains($resolved);
    }
}
