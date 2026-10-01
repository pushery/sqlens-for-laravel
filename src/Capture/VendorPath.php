<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Composer\Autoload\ClassLoader;

/**
 * Whether a file lives inside the dependency tree — asked in ONE place, because two places would
 * disagree.
 *
 * Two layers need the answer and they reach it from different strings. The capture layer classifies
 * an already-resolved path when it decides whether a statement came from a migration of yours; the
 * lint layer asks about the raw path the migrator handed it, before anything has resolved it. Both
 * are "is this vendor code", and answering them separately is how one of them ends up wrong without
 * anything going red.
 *
 * ## Why the RESOLUTION belongs in here, and not just the predicate
 *
 * Sharing only the segment match is the trap, and it is measurable rather than theoretical. A
 * Composer `path` repository symlinks `vendor/<vendor>/<package>` at a directory outside the tree,
 * and the two strings then answer differently:
 *
 *     raw       …/app/vendor/pkg/migrations/0001_x.php   ->  vendor
 *     realpath  …/local/migrations/0001_x.php            ->  NOT vendor
 *
 * A caller matching the raw path would drop the file from the enumeration while the capture layer,
 * matching the resolved one, would bind the same file as a migration of yours. Two opposite answers
 * out of one "shared" predicate — and a guard grepping for the string `vendor` reads both call
 * sites as consistent.
 *
 * So the resolution happens here, and the answer is about where the file REALLY is. A symlinked
 * package is a local checkout you are working on: code you can change, which is the whole
 * distinction the vendor switch draws.
 *
 * ## The project's dependency tree, not every directory called vendor
 *
 * The dependency tree is where Composer installs, and Composer says where that is: every
 * autoloader it registered is keyed by its vendor directory, a `vendor-dir` the project configured
 * included. A `vendor` directory below the project root counts as well, the tree of a nested
 * Composer project. A `vendor` ABOVE the root does not. It used to, because the whole absolute
 * path was searched for the segment, and a checkout that happened to lie in `/builds/vendor/app`
 * then filed every migration of the project as a package's: the same repository gave a different
 * result in another directory, and a Critical in its own migration went silent.
 *
 * A file outside the project and outside every tree Composer registered answers false. Its
 * spelling is not evidence, and false is the direction that costs no finding.
 *
 * Matched as a path SEGMENT: a project directory called `app/Vendors/` or a migration named
 * `2026_01_01_add_vendor_id.php` contains the word and is not the dependency tree, and treating
 * either as vendor code would silence a real finding in a project's own migrations.
 */
final readonly class VendorPath
{
    /**
     * Whether $path resolves to a file inside the dependency tree of the project at $projectRoot.
     *
     * A path that does not exist answers FALSE rather than guessing from its spelling. The two
     * cases that reach here are a file deleted between resolution and judgment and a synthetic path
     * built by a test or a tool, and neither is evidence that something is vendor code — while
     * answering true would drop it from a run silently, which is the direction that costs a finding.
     */
    public static function contains(string $path, string $projectRoot): bool
    {
        $resolved = realpath($path);

        if ($resolved === false) {
            return false;
        }

        foreach (self::composerVendorDirectories() as $directory) {
            if (str_starts_with($resolved, $directory.DIRECTORY_SEPARATOR)) {
                return true;
            }
        }

        $root = realpath($projectRoot);

        if ($root === false) {
            return false;
        }

        $prefix = rtrim($root, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;

        return str_starts_with($resolved, $prefix)
            && in_array('vendor', explode(DIRECTORY_SEPARATOR, dirname(substr($resolved, strlen($prefix)))), true);
    }

    /**
     * The vendor directory of every autoloader Composer registered in this process, resolved.
     *
     * @return list<string>
     */
    private static function composerVendorDirectories(): array
    {
        $directories = [];

        foreach (array_keys(ClassLoader::getRegisteredLoaders()) as $directory) {
            $resolved = realpath($directory);

            if ($resolved !== false) {
                $directories[] = rtrim($resolved, DIRECTORY_SEPARATOR);
            }
        }

        return $directories;
    }
}
