<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Reporting\RunContext;
use Pushery\SQLens\Reporting\Summary\AxisSummary;
use Pushery\SQLens\Reporting\UndeterminedPolicy;

/**
 * Derives the exit code deterministically from a run's result and context. The
 * precedence is explicit and fixed, because two conditions can hold at once and the
 * caller must always get the same code:
 *
 *   1. Misconfiguration beats everything — an invalid configuration never returns 0,
 *      even with no findings (no silent green on a broken setup).
 *   2. Then strict-undetermined — a run with an undetermined check can never be 0
 *      under strict mode; three-valuedness reaches all the way to the exit code.
 *   3. Then a gate breach — a level or severity gate was crossed.
 *   4. Otherwise clean.
 *
 * No command wires this yet; from the capture suite on it is the single source of a
 * run's exit code.
 */
final class ExitCodeResolver
{
    public function resolve(Result $result, RunContext $context, bool $misconfigured = false): ExitCode
    {
        if ($misconfigured) {
            return ExitCode::Misconfiguration;
        }

        if (new UndeterminedPolicy()->verdict($result, $context)->blocks()) {
            return ExitCode::UndeterminedInStrictMode;
        }

        if (AxisSummary::for($result, $context)->breached()) {
            return ExitCode::FindingsAboveGate;
        }

        return ExitCode::Clean;
    }
}
