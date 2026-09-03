<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

/**
 * Writing a formatted file back, without the two ways that destroys work.
 *
 * ## The two failures this exists to prevent
 *
 * **A truncated write.** `file_put_contents()` opens the file for writing before it has the bytes to
 * write, so a process killed in between leaves an EMPTY file where a migration was. On a formatter
 * that walks a whole directory, one interrupted run can empty dozens.
 *
 * **A write that was never needed.** Rewriting a file whose content did not change updates its
 * mtime, which restarts every watcher, rebuilds every cache keyed on it and shows up in `git status`
 * as a modification with an empty diff. A formatter that ran over an unchanged tree should leave the
 * tree untouched.
 *
 * ## Write to a sibling, then rename
 *
 * The temporary file is in the SAME DIRECTORY, not in the system temp: `rename()` is atomic only
 * within one filesystem, and `/tmp` is a different one on most machines — so a cross-device rename
 * silently degrades into copy-then-delete, which is exactly the non-atomic write this avoids.
 */
final readonly class SafeFileWriter
{
    /**
     * Write the contents if they differ, and answer whether anything changed.
     *
     * @return bool true when the file was rewritten, false when it already held these bytes
     */
    public static function write(string $path, string $contents): bool
    {
        if (is_file($path) && file_get_contents($path) === $contents) {
            return false;
        }

        // Sibling, and unique per process: two workers formatting one tree must not write the same
        // temporary name, and a leftover from a killed run must not be picked up as somebody's data.
        $temporary = $path.'.sqlens-'.getmypid().'.tmp';

        // ⚠️ SUPPRESSED, and this is the one place in the package where that is right rather than
        // lazy. Laravel installs an error handler that turns a PHP WARNING into an ErrorException —
        // so an unwritable directory does not return `false` here, it THROWS, and the `false` branch
        // below is unreachable in the only environment this code runs in.
        //
        // Measured: with the warning left unsuppressed, a format run over a directory containing one
        // unwritable file died on that file and reported nothing about the ninety-nine it had
        // already formatted.
        //
        // The return value is the contract this method documents, and suppressing the warning is
        // what makes the contract true.
        if (@file_put_contents($temporary, $contents) === false) {
            return false;
        }

        // Permissions are carried over BEFORE the rename, because the rename is the moment the file
        // becomes the real one. A migration that came out 0600 because the umask happened to be
        // strict is a deploy that fails on a machine running as a different user.
        if (is_file($path) && ($mode = fileperms($path)) !== false) {
            @chmod($temporary, $mode & 0o777);
        }

        // Suppressed for the reason above: a rename that cannot happen — the target is a directory,
        // the filesystem went read-only — must be a `false` this method can act on, not an exception
        // that ends a run over a hundred other files.
        if (! @rename($temporary, $path)) {
            // The rename is the only step that can leave a stray file behind, and leaving one in a
            // migrations directory is worse than the failed write: the next run reads it as a
            // migration.
            @unlink($temporary);

            return false;
        }

        return true;
    }
}
