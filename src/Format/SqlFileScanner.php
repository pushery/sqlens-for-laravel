<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Which files a format run touches, in one order.
 *
 * ## Sorted, and that is not tidiness
 *
 * A directory iterator returns files in whatever order the filesystem holds them, which differs
 * between machines and between a fresh checkout and one that has been edited. A formatter's REPORT
 * would then list the same files in a different order on two machines, and a `--check` step's output
 * could not be diffed against a previous run.
 *
 * ## `.sql` ONLY — and this is the most consequential line in the file
 *
 * A Laravel migration is a PHP file whose SQL, where there is any, lives inside a heredoc. Running a
 * SQL formatter over that file does not format the SQL: it reads PHP as SQL, and rewrites the whole
 * file as though it were a statement. That is not a bad diff, it is a destroyed migration — and the
 * run reports it as `reformatted`.
 *
 * A first draft of this scanner took `.php` as well. Nothing about it looked wrong.
 *
 * Formatting SQL inside a heredoc needs a PHP parser, a way to find the heredocs that hold SQL, and
 * a way to write the formatted text back at the original indentation. That is a real feature and it
 * is deliberately NOT in v1.x — the scope decision, not an oversight.
 *
 * ## Generated files are left alone
 *
 * `database/schema/*.sql` is written by `schema:dump`, from the database, in whatever shape the
 * dumper produces. Reformatting it makes the next dump a large diff against a file nobody edits, and
 * a project would see that diff on every deploy.
 */
final readonly class SqlFileScanner
{
    /**
     * Whether this path is a file this formatter may touch.
     *
     * Two conditions and both are absolute: the extension is `.sql`, and it is not a generated
     * schema dump.
     */
    private static function isFormattable(string $path): bool
    {
        // ⚠️ NOT IN SCOPE is a different answer from SKIPPED, and the difference is why this is a
        // filter rather than a check inside the loop. A `.php`, `.blade.php`, `.md` or `.json` file
        // in a formatted directory is not a file this suite could not handle — it is a file this
        // suite has nothing to do with, and reporting it as `undetermined` would fill every run's
        // output with entries nobody can act on.
        //
        // A skip carries a reason because somebody might fix it. This carries none because there is
        // nothing to fix.
        if (! str_ends_with(strtolower($path), '.sql')) {
            return false;
        }

        // `database/schema/` is `schema:dump`'s output directory, matched as a path segment rather
        // than by prefix so it works for a project that keeps its database directory somewhere else.
        return ! str_contains(str_replace('\\', '/', $path), '/database/schema/');
    }

    /**
     * @param  list<string>  $paths
     * @return list<string> absolute paths, sorted
     */
    public static function scan(array $paths): array
    {
        $files = [];

        foreach ($paths as $path) {
            if (is_file($path)) {
                // A path named EXPLICITLY still has to be a `.sql` file. `--path` is not an override
                // of the scope decision — somebody naming a migration by hand would otherwise get
                // the destroyed-migration outcome the class docblock describes, having asked for it
                // by accident.
                if (self::isFormattable($path)) {
                    $files[] = $path;
                }

                continue;
            }

            if (! is_dir($path)) {
                continue;
            }

            /** @var iterable<SplFileInfo> $found */
            $found = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS));

            foreach ($found as $file) {
                if ($file->isFile() && self::isFormattable($file->getPathname())) {
                    $files[] = $file->getPathname();
                }
            }
        }

        // Unique because two configured paths can overlap — a project naming both
        // `database/migrations` and its parent would otherwise format every file twice, and the
        // second pass would report the first pass's own changes.
        $files = array_values(array_unique($files));
        sort($files, SORT_STRING);

        return $files;
    }
}
