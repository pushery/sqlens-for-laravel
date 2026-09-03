<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Pushery\SQLens\Config\ConfigSchema;
use Pushery\SQLens\Severity\Severity;

/**
 * `--min-severity`, resolved once for every command that offers it.
 *
 * The security severity floor is its own axis, separate from the cumulative level: `--level` asks
 * how strict a project wants to be about craft, and this asks what risk is worth stopping a
 * pipeline for. A run reports both, and neither lifts the other's gate.
 *
 * Its own trait rather than a member of {@see SharesRunOptions}, for the reason that trait's
 * companion {@see WritesReportOutput} states: a command may offer this flag without offering
 * `--level` or `--category`, and Larastan resolves an option access against the command's real
 * signature. `sqlens:security` is exactly that command — a security finding is weighed HERE, and a
 * level would let a project's strictness appetite silently withhold a security rule.
 */
trait ResolvesMinSeverity
{
    /**
     * The severity floor for this run, or false when the flag names something that is not one.
     *
     * Returned as a STRING rather than a `Severity`, because `none` is a legal answer and is not a
     * severity. The caller writes it straight onto the config the collector already reads, so the
     * precedence base → profile → flag holds through one value in one place instead of a threshold
     * threaded in parallel with the config's.
     *
     * Same hardness as the config key: an unknown value is a named misconfiguration, never a quiet
     * fall back to a floor nobody chose. That failure is the confident kind — a run with no floor
     * is GREEN — so it has to be refused where it is typed.
     */
    private function validatedMinSeverity(): string|false|null
    {
        $requested = $this->option('min-severity');

        if (! is_string($requested) || $requested === '') {
            return null;
        }

        if ($requested === ConfigSchema::SEVERITY_GATE_OFF || Severity::tryFrom($requested) instanceof Severity) {
            return $requested;
        }

        $this->stderr()->writeln($this->translate('sqlens::messages.commands.invalid_min_severity', [
            'severity' => $requested,
            'available' => implode(', ', array_map(static fn (Severity $case): string => $case->value, Severity::cases())),
        ]));

        return false;
    }
}
