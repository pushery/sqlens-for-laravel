<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use RuntimeException;

/**
 * The drift exclude file exists and cannot be read with confidence. Every case here ends the run
 * with the misconfiguration exit status.
 *
 * The strictness is the same one {@see UnreadableBaseline} argues for, and for a sharper reason:
 * this file decides which schema differences a project stops being told about. Half-understanding it
 * is worse than not having it — reading it loosely hides differences nobody accepted, and ignoring
 * it silently buries the real ones under the accepted ones. Both are quiet, so the run stops and
 * says which file and why.
 */
final class UnreadableDriftExcludes extends RuntimeException
{
    /**
     * The file is there and gave us nothing — it is empty, or the read failed.
     *
     * One factory for both on purpose. A read that fails on a file `is_file()` just accepted needs
     * permissions the reader does not have, and that state cannot be produced on a container running
     * as root — which this package's CI does. A branch of its own would therefore be a line no run
     * can enter, under a coverage floor that admits no exemption. Folding it in with the empty file
     * loses nothing a reader needed: both mean this file exists and told us nothing, both are acted
     * on the same way, and `src/Audit/ProjectManifest` folds the same pair for the same reason.
     */
    public static function yieldedNothing(string $path): self
    {
        return new self(sprintf(
            'The drift exclude file at "%s" is there and yielded nothing — it is empty, or it could not be read. Check its permissions, or regenerate it with sqlens:drift --update-excludes.',
            $path,
        ));
    }

    public static function notJson(string $path, string $detail): self
    {
        return new self(sprintf(
            'The drift exclude file at "%s" is not valid JSON (%s). Regenerate it with sqlens:drift --update-excludes.',
            $path,
            $detail,
        ));
    }

    public static function notAnObject(string $path, string $found): self
    {
        return new self(sprintf(
            'The drift exclude file at "%s" is not a JSON object (found %s). Regenerate it with sqlens:drift --update-excludes.',
            $path,
            $found,
        ));
    }

    public static function missingVersion(string $path): self
    {
        return new self(sprintf(
            'The drift exclude file at "%s" carries no "schema_version", so its format cannot be determined. SQLens does not guess a version.',
            $path,
        ));
    }

    /**
     * A version this build does not know — in EITHER direction, and the message says which.
     *
     * A newer file comes from a build that could express something this one cannot, so reading the
     * parts we recognize would silently drop the rest. An older one would need a migration path, and
     * there is none to run yet.
     */
    public static function unsupportedVersion(string $path, mixed $found, int $supported): self
    {
        return new self(sprintf(
            'The drift exclude file at "%s" declares schema_version %s; this build reads %d. %s',
            $path,
            is_scalar($found) ? self::render($found) : get_debug_type($found),
            $supported,
            is_int($found) && $found > $supported
                ? 'It was written by a newer SQLens — upgrade rather than let this run interpret half of it.'
                : 'There is no migration path for that version, so it is refused instead of read approximately.',
        ));
    }

    /**
     * A scalar as it should appear in a message — a string quoted, everything else plain.
     *
     * Hand-rolled because the architecture preset forbids `var_export`, and rightly: it is a
     * debugging tool whose output shape is not something a user-facing message should inherit.
     */
    private static function render(string|int|float|bool $found): string
    {
        return match (true) {
            is_string($found) => '"'.$found.'"',
            is_bool($found) => $found ? 'true' : 'false',
            default => (string) $found,
        };
    }

    public static function entriesNotAList(string $path, string $found): self
    {
        return new self(sprintf(
            'The drift exclude file at "%s" has "entries" of type %s, but it must be a list.',
            $path,
            $found,
        ));
    }

    /** An entry that is unusable. The index is included because entries carry no id to name. */
    public static function malformedEntry(string $path, int $index, string $why): self
    {
        return new self(sprintf(
            'The drift exclude file at "%s" has an unusable entry at position %d: %s.',
            $path,
            $index,
            $why,
        ));
    }

    /**
     * An entry with no reason — its own case, because it is the one a person writes by hand.
     *
     * Named rather than folded into `malformedEntry` so the message can carry the rule instead of a
     * type complaint: the reason is what makes an exclusion reviewable, and somebody who left it out
     * needs to be told that, not told that a key is missing.
     */
    public static function entryWithoutReason(string $path, int $index, string $describes): self
    {
        return new self(sprintf(
            'The drift exclude file at "%s" excludes %s at position %d without a "reason". '
            .'Every exclusion needs one: an entry that does not say why it exists cannot be reviewed, '
            .'and six months from now nobody can tell a deliberate decision from a silenced finding.',
            $path,
            $describes,
            $index,
        ));
    }

    /**
     * Entries that matched nothing this run.
     *
     * The same rule an unknown rule id in an ignore list gets, and for the same reason: excludes that
     * nobody prunes grow into a ceiling under which real drift disappears. A stale entry is reported
     * with what it says, so the line is findable.
     *
     * @param  list<string>  $described
     */
    public static function staleEntries(string $path, array $described): self
    {
        return new self(sprintf(
            'The drift exclude file at "%s" has %d entr%s that matched nothing in this run: %s. '
            .'Either the difference is gone — then delete the line — or the object was renamed and '
            .'the entry now hides nothing while looking as though it does.',
            $path,
            count($described),
            count($described) === 1 ? 'y' : 'ies',
            implode('; ', $described),
        ));
    }
}
