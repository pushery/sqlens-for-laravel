<?php

declare(strict_types=1);

namespace Pushery\SQLens;

/**
 * Where a path this package is given points: one anchor for every path input.
 *
 * An absolute path stays as it is. A relative one resolves against the project root, which is how
 * Laravel's own `migrate --path` reads it and how the configuration documents its path keys
 * (repo-relative). Resolved against the working directory instead, the same configuration would
 * mean a different directory depending on where `artisan` was started from: a hook started from a
 * monorepo's root would find no migrations, and a file inside a configured path would be refused
 * as outside it.
 */
final readonly class ProjectPath
{
    /** The path, anchored at $projectRoot unless it is absolute already. */
    public static function anchored(string $path, string $projectRoot): string
    {
        if (self::isAbsolute($path)) {
            return $path;
        }

        return rtrim($projectRoot, '/\\').DIRECTORY_SEPARATOR.ltrim($path, '/\\');
    }

    /**
     * The repo-relative form of a path: what a finding shows, and the reason two machines agree.
     *
     * A path outside the project root stays as it is. Cut to look relative, it still carried the
     * machine's directory layout and read like a path in the repository, so a SARIF consumer
     * resolved it against the repository and pointed at a file that is not there. A package linked
     * through a Composer `path` repository is the ordinary way to get one: PHP reports its
     * migrations under the directory the link resolves to.
     */
    public static function relative(string $path, string $projectRoot): string
    {
        $root = rtrim($projectRoot, '/\\').'/';

        return str_starts_with($path, $root) ? substr($path, strlen($root)) : $path;
    }

    /** Unix, Windows drive, or UNC absolute. */
    public static function isAbsolute(string $path): bool
    {
        return preg_match('#^(?:/|\\\\|[A-Za-z]:[/\\\\])#', $path) === 1;
    }
}
