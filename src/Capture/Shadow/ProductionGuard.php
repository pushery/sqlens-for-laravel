<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

/**
 * The one gate every database-creating mode passes through — shadow now, and the
 * roundtrip and drift comparator later. A mode that creates and drops databases
 * must never run against production by accident, and this is the single place
 * that enforces it, so the guarantee cannot drift between three call sites.
 *
 * The checks are CUMULATIVE and ORDERED, and the order encodes the priority of the
 * refusals:
 *
 *   1. The environment must be on the allowed list. This is checked FIRST and is
 *      NOT overridable by `--force` — `--force` answers "yes, I mean it" to a
 *      confirmation, it does not answer "yes, run in production". A force flag that
 *      could override the environment would defeat the whole guard.
 *   2. The target connection must not be a production connection.
 *   3. The run must be confirmed: `--force`, or an interactive run the user
 *      confirmed. A non-interactive run without `--force` is refused rather than
 *      assumed-yes.
 *
 * A refusal is a decision, not an exception: the guard returns a blocked
 * GuardDecision with a named reason, which the captor turns into an undetermined
 * result. A blocked run is never a pass.
 *
 * The guard evaluates plain inputs, not a live console — a command gathers the
 * environment, the flags and the connection's production status and hands them
 * over. That keeps the safety logic unit-testable without a terminal and makes it
 * reusable by every mode that needs it, exactly as the ticket requires (no
 * command-private trait).
 */
final readonly class ProductionGuard
{
    /**
     * @param  list<string>  $allowedEnvironments  the environments the mode may run in
     */
    public function evaluate(
        string $environment,
        array $allowedEnvironments,
        bool $targetIsProductionConnection,
        bool $force,
        bool $interactive,
        bool $confirmed,
    ): GuardDecision {
        if (! in_array($environment, $allowedEnvironments, true)) {
            return GuardDecision::block(GuardBlockReason::DisallowedEnvironment, $environment, $force);
        }

        if ($targetIsProductionConnection) {
            return GuardDecision::block(GuardBlockReason::ProductionConnection, $environment, $force);
        }

        // Confirmation: --force is the explicit yes; otherwise an interactive run
        // that the user confirmed passes, and a non-interactive run without --force
        // is refused rather than assumed-yes.
        if (! $force && (! $interactive || ! $confirmed)) {
            return GuardDecision::block(GuardBlockReason::NotConfirmed, $environment, $force);
        }

        return GuardDecision::allow($environment, $force);
    }
}
