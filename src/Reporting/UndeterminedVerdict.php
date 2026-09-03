<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting;

/**
 * How the undetermined findings of a run affect its gate — a third class, never a
 * boolean. The policy must NOT relabel an undetermined as a `fail`; an undetermined
 * stays its own outcome, and this enum only says whether, under the run's
 * strictness, it blocks the gate.
 */
enum UndeterminedVerdict: string
{
    /** The run has no undetermined findings at all. */
    case None = 'none';

    /** Undetermined findings exist but are tolerated (normal mode) — reported, not blocking. */
    case Tolerated = 'tolerated';

    /** Undetermined findings exist and strict-undetermined mode escalates them to blocking. */
    case Escalated = 'escalated';

    /** Whether this verdict blocks the run's gate (only the escalated case does). */
    public function blocks(): bool
    {
        return $this === self::Escalated;
    }
}
