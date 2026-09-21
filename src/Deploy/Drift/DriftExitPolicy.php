<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

use Pushery\SQLens\Console\ExitCode;

/**
 * The exit code a drift run ends with — the whole verdict, in one place and with no I/O.
 *
 * It is its own class because the decision has five inputs and three outcomes, and because getting
 * it wrong is silent: an exit code nobody reads until a deploy script acts on it. Kept pure, every
 * combination is a test rather than a scenario somebody has to stage.
 *
 * ## ⚠️ THE DOCBLOCK SAID "in one place" WHILE THE COMMAND DECIDED ONE CASE ITSELF
 *
 * `DriftCommand` used to answer the unbuildable-reference case inline, before ever reaching this
 * class — and it answered it differently: `UndeterminedInStrictMode` in **report** mode, where this
 * policy says report mode never blocks. Under the shipped defaults that was the ordinary CI outcome
 * rather than an edge: the reference is a shadow replay, `deploy.shadow.allowed_environments` is
 * `['local', 'testing']`, so in a `ci` environment the production guard refuses, no reference is
 * built, and a report run exited **3**.
 *
 * Four sources described that case and three of them agreed with each other: the command's class
 * docblock (*"the default prints everything and exits clean"*), this policy's report arm, and the
 * `--allow-undetermined` help text. The behavior was the outlier, so the behavior moved.
 *
 * ⚠️ **Report mode exiting clean over an unbuildable reference is NOT a silent green, and the
 * distinction is the condition the command's own docblock names:** the mode and the named reason are
 * printed. A report run makes no claim about the schema — that is what gate mode is for — and a mode
 * that turns red on its first run against a real database is switched off rather than adopted. In
 * **gate** mode an unbuildable reference still blocks, because there the exit code IS the claim.
 */
final readonly class DriftExitPolicy
{
    /**
     * @param  int  $entries  drift findings — objects the two sides disagree about
     * @param  int  $blindSpots  object types one side could not read at all
     * @param  bool  $referenceBuilt  whether an expectation could be built at all — false is the
     *                                widest blind spot there is, and it has no parameter default on
     *                                purpose: a caller that could not build a reference and forgets
     *                                to say so is exactly how a silent green happens
     */
    public static function decide(DriftRunMode $mode, int $entries, int $blindSpots, bool $allowUndetermined, bool $referenceBuilt): ExitCode
    {
        // Report mode never blocks, whatever it found — including finding nothing to compare
        // against. The findings are still printed in full, and the mode is printed with them; that
        // line is what keeps this from being a silent green.
        if ($mode === DriftRunMode::Report) {
            return ExitCode::Clean;
        }

        // A real finding blocks, and the hatch does not reach it. `--allow-undetermined` opens
        // exactly one door: a run blocked ONLY by checks that could not answer. A finding is a fact
        // about the database rather than a statement about this run's reach.
        if ($entries > 0) {
            return ExitCode::FindingsAboveGate;
        }

        // Nothing to compare against: the run did not establish that there is no drift, it
        // established that it could not look. Those are different results and only one of them is
        // good news, so an empty finding list here is NOT clean.
        //
        // An unbuildable reference joins this arm rather than getting its own, because it is the same
        // statement about reach with a wider subject — no object type could be read instead of some.
        // Giving it a second arm would mean a second place where the hatch has to be honored, and
        // the one that got forgotten is why this parameter exists.
        if (! $referenceBuilt || $blindSpots > 0) {
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
    public static function waived(DriftRunMode $mode, int $entries, int $blindSpots, bool $allowUndetermined, bool $referenceBuilt): bool
    {
        return $mode === DriftRunMode::Gate
            && $entries === 0
            && (! $referenceBuilt || $blindSpots > 0)
            && $allowUndetermined;
    }
}
