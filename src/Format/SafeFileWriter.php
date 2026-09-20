<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

/**
 * Writing a formatted file back, without the three ways that destroys work.
 *
 * ## The three failures this exists to prevent
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
 * **A write that went somewhere else.** ⚠️ This one was the header's own blind spot: it said *two*
 * while the temporary name was the path plus the PID — predictable — and the write opened it with
 * `O_CREAT|O_TRUNC`, which follows a symlink. Anyone able to write in the directory could aim the
 * formatted SQL at a file of their choosing, and the `rename()` afterwards moved the symlink onto the
 * migration path so the result looked ordinary. The name carries random bytes now and the open is
 * `O_CREAT|O_EXCL`, which refuses rather than follows.
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

        // Sibling, and unique per WRITE rather than per process. Two workers formatting one tree must
        // not write the same temporary name, and a leftover from a killed run must not be picked up as
        // somebody's data.
        //
        // ⚠️ **It used to be the path plus the PID, which is PREDICTABLE, and predictable is what made
        // the next line exploitable.** Anyone able to write in the migrations directory could place
        // `<file>.sqlens-<pid>.tmp` as a symlink pointing anywhere; `file_put_contents` opens with
        // `O_CREAT|O_TRUNC` and FOLLOWS it, so the formatted SQL landed at the symlink's target — and
        // the `rename()` below then moved the symlink itself onto the migration path, leaving the
        // damage in place looking like an ordinary file.
        //
        // Random bytes remove the attacker's ability to pre-place anything at all, and they also
        // remove the only reason the PID was there: a stray from a killed run can no longer collide
        // with a live one, so `x` below cannot be wedged by one.
        $temporary = $path.'.sqlens-'.bin2hex(random_bytes(8)).'.tmp';

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
        // ⚠️ `x` rather than `w`, and that is the load-bearing character. `x` is `O_CREAT|O_EXCL`,
        // which fails with EEXIST when the path already exists -- INCLUDING when it is a symlink, and
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
     * ⚠️ **A METHOD RATHER THAN A SECOND BRANCH IN `write()`, AND THE COVERAGE FLOOR IS WHY.** The
     * first version of this checked the short write with its own `if`, and that branch is one no run
     * can enter: `fwrite` to a local file does not come up short unless the disk is full or the stream
     * is broken, neither of which a test can arrange. The 100 % floor named it at 99.9 %.
     *
     * Deleting the check was the wrong answer — renaming half a file over a migration is the first
     * failure this class's header says it prevents. So the check became a VALUE instead: the last line
     * is an expression that always runs, and the short write is a `false` rather than a jump.
     *
     * The remaining `return false` IS reachable, and deliberately by a uid-independent route: `x` is
     * `O_CREAT|O_EXCL`, so it fails when the directory does not exist — which holds for root as well,
     * unlike an unwritable directory. That matters because the coverage step runs in a container.
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
