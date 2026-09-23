<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

/**
 * Writing a formatted file back, without the three ways that destroys work.
 *
 * ## The three failures this exists to prevent
 *
 * **A truncated write.** `file_put_contents()` opens the file for writing before it has the bytes to
 * write, so a process killed in between leaves an empty file where a migration was. On a formatter
 * that walks a whole directory, one interrupted run can empty dozens.
 *
 * **A write that was never needed.** Rewriting a file whose content did not change updates its
 * mtime, which restarts every watcher, rebuilds every cache keyed on it and shows up in `git status`
 * as a modification with an empty diff. A formatter that ran over an unchanged tree should leave the
 * tree untouched.
 *
 * **A write that went somewhere else.** A predictable temporary name opened with `O_CREAT|O_TRUNC`
 * follows a symlink: anyone able to write in the directory could aim the formatted SQL at a file of
 * their choosing, and the `rename()` afterwards would move the symlink onto the migration path so
 * the result looked ordinary. The name carries random bytes and the open is `O_CREAT|O_EXCL`, which
 * refuses rather than follows.
 *
 * ## Write to a sibling, then rename
 *
 * The temporary file is in the same directory, not in the system temp: `rename()` is atomic only
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

        // Sibling, and unique per write rather than per process. Two workers formatting one tree must
        // not write the same temporary name, and a leftover from a killed run must not be picked up as
        // somebody's data.
        //
        // Random, because a predictable name — the path plus the PID, say — is what would make the
        // write exploitable. Anyone able to write in the migrations directory could place that name as
        // a symlink pointing anywhere; `file_put_contents` opens with `O_CREAT|O_TRUNC` and follows
        // it, so the formatted SQL would land at the symlink's target — and the `rename()` below would
        // then move the symlink itself onto the migration path, leaving the damage in place looking
        // like an ordinary file.
        //
        // Random bytes remove the ability to pre-place anything at all, and a stray from a killed run
        // cannot collide with a live one either, so `x` below cannot be wedged by one.
        $temporary = $path.'.sqlens-'.bin2hex(random_bytes(8)).'.tmp';

        // Suppressed, and this is the one place in the package where that is right rather than
        // lazy. Laravel installs an error handler that turns a PHP warning into an ErrorException —
        // so an unwritable directory would not return `false` here, it would throw, and a format run
        // over a directory containing one unwritable file would die on that file and report nothing
        // about the ninety-nine it had already formatted.
        //
        // The return value is the contract this method documents, and suppressing the warning is
        // what makes the contract true.
        //
        // `x` rather than `w`, and that is the load-bearing character. `x` is `O_CREAT|O_EXCL`,
        // which fails with EEXIST when the path already exists -- including when it is a symlink, and
        // including a symlink whose target does not exist. `w` would create or truncate whatever the
        // name resolves to. So this refuses rather than follows, which is the direction a writer named
        // `Safe` has to fail in.
        if (! self::writtenExclusively($temporary, $contents)) {
            // Best-effort cleanup, and it is correct in both of the cases that get here. When the open
            // failed nothing was created and this is a no-op; when the write came up short the stray
            // must go, for the reason the rename branch below gives -- the next run would read it as a
            // migration.
            @unlink($temporary);

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

    /**
     * Create the temporary file and write all of it, or answer false.
     *
     * The short write is checked as a value rather than as a branch of its own: `fwrite` to a local
     * file does not come up short unless the disk is full or the stream is broken, so a separate `if`
     * would be a branch no run can enter. The check itself stays — renaming half a file over a
     * migration is the first failure this class's header says it prevents — as an expression that
     * always runs, where the short write is a `false` rather than a jump.
     *
     * The remaining `return false` is reachable by a uid-independent route: `x` is `O_CREAT|O_EXCL`,
     * so it fails when the directory does not exist — which holds for root as well, unlike an
     * unwritable directory.
     */
    private static function writtenExclusively(string $temporary, string $contents): bool
    {
        // `x` is `O_CREAT|O_EXCL`: it refuses a path that already exists, including a symlink and
        // including one whose target does not. See the class docblock for why that is load-bearing.
        $handle = @fopen($temporary, 'x');

        if (! is_resource($handle)) {
            return false;
        }

        $written = @fwrite($handle, $contents);
        @fclose($handle);

        return $written === strlen($contents);
    }
}
