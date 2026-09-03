<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

/**
 * How a tool invocation ended — three-valued, like every other verdict in this package.
 *
 * A tool that ran and a tool that could not be started are different facts, and collapsing
 * them is how "the check passed" comes to mean "the check never happened". The exit code
 * alone cannot carry the distinction: a run that timed out and a run that exited non-zero
 * both look like failure, but only one of them measured anything.
 */
enum ToolRunOutcome: string
{
    /** The process started, finished within its bound, and reported an exit code. */
    case Completed = 'completed';

    /** The process hit its time bound and was terminated — nothing was measured. */
    case TimedOut = 'timed_out';

    /** The process never started: not executable, missing interpreter, no permission. */
    case StartFailed = 'start_failed';

    /**
     * Whether the invocation produced a usable exit code.
     *
     * Deliberately not "was successful": a linter that finds problems exits non-zero and has
     * completed perfectly well. Whether that exit code means trouble is the caller's reading,
     * not this enum's.
     */
    public function produced(): bool
    {
        return $this === self::Completed;
    }
}
