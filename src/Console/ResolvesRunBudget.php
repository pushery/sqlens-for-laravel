<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Illuminate\Contracts\Config\Repository;

/**
 * `--budget`, resolved once for both deploy commands so they cannot disagree about what it accepts.
 *
 * **An unusable value is refused by name, never dropped.** Read as
 * `ctype_digit($budget) ? (int) $budget : null`, `--budget=abc` would come back as `null`, the
 * signal for *"not given, take the configured value"*, and run with the configured default without a
 * word — leaving an operator believing they had bounded the run they were about to gate a deploy on.
 *
 * The principle is written down in {@see AuditCommand}: *"an unknown value is a named
 * misconfiguration"*. `--level=12` and `--debt=recrod` are refused by name, and so is `--budget=abc`.
 *
 * ## Why a trait rather than a method on each command
 *
 * The same reason {@see SharesRunOptions} gives for `--level`: *"two copies of 'reject a level above
 * 9' would eventually disagree about whether 10 is an error or a clamp, and the disagreement would
 * be invisible because each command's own test would still pass."* That had already happened here —
 * `sqlens:postdeploy` required `> 0` and `sqlens:predeploy` accepted `0`, so the same flag meant two
 * different things depending on which gate you typed it at.
 *
 * ## Why it does not live in `SharesRunOptions`
 *
 * That trait's own note says a command offering neither `--level` nor `--category` cannot use it,
 * and the deploy commands offer neither. One concern per trait is the shape this directory already
 * has — `ResolvesMinSeverity`, `ResolvesProfile`, `WritesReportOutput`.
 *
 * The three-valued return is the same contract as the rest of the family: `false` means "already
 * rejected, and the reason is on STDERR", `null` means "not given, take the configured value", and
 * those two must never collapse into each other.
 */
trait ResolvesRunBudget
{
    /**
     * The run's budget in milliseconds, or false when the flag was given and is not one.
     *
     * Zero is refused along with the rest, and that is a decision rather than an oversight: a budget
     * of zero milliseconds is not a fast run, it is a run whose deadline has already passed before
     * the first statement. Whoever typed it meant something else.
     */
    private function validatedBudgetMs(): int|false|null
    {
        $budget = $this->option('budget');

        if (! is_string($budget) || $budget === '') {
            return null;
        }

        if (! ctype_digit($budget) || (int) $budget < 1) {
            // `outputErrorLine` plus `translate` rather than `stderr()`: both users of this trait
            // define the former and inherit the latter from ResolvesProfile, and neither has the
            // `WritesReportOutput` plumbing that SharesRunOptions writes through.
            $this->outputErrorLine($this->translate('sqlens::messages.commands.invalid_budget', ['budget' => $budget]));

            return false;
        }

        return (int) $budget;
    }

    /**
     * The configured fallback for a key, when the flag was not given.
     *
     * Read here rather than in each command so the "positive integer or the shipped default" rule is
     * one implementation too. The KEY stays the caller's, because the two gates deliberately read
     * different ones — `sqlens:postdeploy` moved off `preflight.budget_ms` on 2026-08-24 so that
     * raising the gate's allowance stopped silently raising the aftercare's.
     */
    private function configuredBudgetMs(Repository $config, string $key, int $fallback): int
    {
        $configured = $config->get($key);

        return is_int($configured) && $configured > 0 ? $configured : $fallback;
    }
}
