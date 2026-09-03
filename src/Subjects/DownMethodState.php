<?php

declare(strict_types=1);

namespace Pushery\SQLens\Subjects;

use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * What a migration's `down()` amounts to, as read from the file rather than from a run.
 *
 * A migration whose `down()` is absent or does nothing cannot be rolled back — and the moment
 * that matters is the moment a deploy is already going wrong, which is the worst possible time
 * to discover it. The fact is syntactic, so it is answered syntactically.
 *
 * ## Why this is decided statically, and not by running the migration
 *
 * A roundtrip cannot see it. A missing `down()` produces no statements at all, and neither does
 * one whose body is empty — so at runtime both are indistinguishable from a `down()` that
 * legitimately had nothing to undo. The file is the only place the difference exists.
 *
 * It is also the check a pre-commit hook wants: it needs no database, so it survives in the
 * sub-second single-file fast path where a shadow-database check could never run.
 *
 * {@see UndeterminedReason::RoundtripNoDownMethod} answers the
 * neighboring RUNTIME question — the roundtrip had no down leg to replay. Different question,
 * different moment, no overlap.
 */
enum DownMethodState: string
{
    /** The migration declares a `down()` with statements in it. */
    case Present = 'present';

    /** The migration declares no `down()` at all. */
    case Missing = 'missing';

    /**
     * A `down()` exists but its body holds no statements — an empty body, or only comments.
     *
     * Kept apart from {@see self::Missing} because the two are different mistakes with the same
     * consequence: one was never written, the other was written and then hollowed out (or
     * deliberately stubbed). A reader needs to know which, and a rule's message reads
     * differently for each.
     */
    case Empty = 'empty';

    /** Whether the migration can be rolled back at all — the question a rule actually asks. */
    public function isReversible(): bool
    {
        return $this === self::Present;
    }
}
