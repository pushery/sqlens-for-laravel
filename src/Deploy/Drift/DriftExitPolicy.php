<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

use Pushery\SQLens\Console\ExitCode;

/**
 * The exit code a drift run ends with — the whole verdict, in one place and with no I/O.
 *
 * It is its own class because the decision has four inputs and three outcomes, and because getting
 * it wrong is silent: an exit code nobody reads until a deploy script acts on it. Kept pure, every
 * combination is a test rather than a scenario somebody has to stage.
 */
final readonly class DriftExitPolicy
{
    /**
     * @param  int  $entries  drift findings — objects the two sides disagree about
     * @param  int  $blindSpots  object types one side could not read at all
     */
    public static function decide(DriftRunMode $mode, int $entries, int $blindSpots, bool $allowUndetermined): ExitCode
    {
        // Report mode never blocks, whatever it found. The findings are still printed in full, and
        // the mode is printed with them — that line is what keeps this from being a silent green.
        if ($mode === DriftRunMode::Report) {
            return ExitCode::Clean;
        }

        // A real finding blocks, and the hatch does not reach it. `--allow-undetermined` opens
        // exactly one door: a run blocked ONLY by checks that could not answer. A finding is a fact
        // about the database rather than a statement about this run's reach.
        if ($entries > 0) {
            return ExitCode::FindingsAboveGate;
        }

        // Nothing to compare against on some object type: the run did not establish that there is no
        // drift, it established that it could not look. Those are different results and only one of
        // them is good news, so an empty finding list here is NOT clean.
        if ($blindSpots > 0) {
            return $allowUndetermined ? ExitCode::Clean : ExitCode::UndeterminedInStrictMode;
        }

        return ExitCode::Clean;
    }

    /**
     * Whether this run's verdict was WAIVED — blocked only by what it could not read, and let
     * through by the hatch.
     *
     * Recorded in the run header rather than inferred later, because a waived green and an earned
     * one are otherwise the same exit code, the same tick and the same report, and "drift passed"
     * would mean two different things nobody can separate afterwards.
     */
    public static function waived(DriftRunMode $mode, int $entries, int $blindSpots, bool $allowUndetermined): bool
    {
        return $mode === DriftRunMode::Gate && $entries === 0 && $blindSpots > 0 && $allowUndetermined;
    }
}
