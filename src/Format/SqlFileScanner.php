<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

use FilesystemIterator;
use RecursiveCallbackFilterIterator;
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
 *
 * ## A symlink is never followed, and that is a WRITE decision
 *
 * `format` is the only suite that writes, so a symlink out of a configured root is a way for a run
 * to rewrite a file outside its blast radius — and for a cycle to make the walk never finish. Both
 * are refused by rejecting the link itself rather than by trying to detect where it goes: a link is
 * not a file this project keeps here, whatever it points at.
 *
 * ## Everything else comes from {@see FormatDiscovery}
 *
 * The extension set, the exclude globs and the directories no run descends into live there, next to
 * the reasoning for each. This class walks; it does not decide.
 */
final readonly class SqlFileScanner
{
    /**
     * @param  list<string>  $paths
     * @return list<string> absolute paths, sorted
     */
    public static function scan(array $paths, ?FormatDiscovery $discovery = null): array
    {
        $discovery ??= FormatDiscovery::defaults();
        $files = [];

        foreach ($paths as $path) {
            if (is_file($path)) {
                // A path named EXPLICITLY is still judged. `--path` is not an override of the scope
                // decision — somebody naming a migration by hand would otherwise get the
                // destroyed-migration outcome the class docblock describes, having asked for it by
                // accident.
                if ($discovery->admits($path)) {
                    $files[] = $path;
                }

                continue;
            }

            if (! is_dir($path)) {
                continue;
            }

            $files = [...$files, ...self::walk($path, $discovery)];
        }

        // Unique because two configured paths can overlap — a project naming both
        // `database/migrations` and its parent would otherwise format every file twice, and the
        // second pass would report the first pass's own changes.
        $files = array_values(array_unique($files));

        // ⚠️ `SORT_STRING`, and the flag is the whole point rather than a default somebody typed.
        // It compares BYTES; `SORT_LOCALE_STRING` would compare by the ambient collation, and the
        // same tree would then produce a different order under `de_DE.UTF-8` than under `C`. A
        // `--check` report that reorders itself by environment cannot be diffed against yesterday's,
        // which is the whole reason the list is sorted at all.
        sort($files, SORT_STRING);

        return $files;
    }

    /**
     * Walk one directory, pruning at the directory level rather than filtering at the end.
     *
     * Pruning is what `NEVER_DESCEND` means: a run that walked all of `vendor/` and then discarded
     * the results would be correct and would still spend the time, on the one directory most likely
     * to hold tens of thousands of files.
     *
     * @return list<string>
     */
    private static function walk(string $path, FormatDiscovery $discovery): array
    {
        $walkable = new RecursiveCallbackFilterIterator(
            new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
            static fn (SplFileInfo $entry): bool => ! $entry->isLink()
                && (! $entry->isDir() || $discovery->mayDescend($entry->getPathname())),
        );

        $files = [];

        /** @var iterable<SplFileInfo> $found */
        $found = new RecursiveIteratorIterator($walkable);

        foreach ($found as $file) {
            if ($file->isFile() && $discovery->admits($file->getPathname())) {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }
}
