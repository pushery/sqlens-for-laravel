<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Translation\Translator;
use Pushery\SQLens\Config\ConfigInspection;
use Pushery\SQLens\Config\ConfigValidator;
use Pushery\SQLens\ShippedLocale;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * The one check every command owes its user before it does anything else.
 *
 * ## The failure this exists to stop
 *
 * A key the package does not know is a key the package IGNORES, and ignoring is silent. A run with
 * `levl: 3` uses the default level and comes back green because it checked less. A run with
 * `audit.tenancy.mode: 'explicits'` compares unequal to `'explicit'`, falls into the signal branch,
 * and behaves as if the project had declared no reference tenant at all — while the project
 * believes it declared one. Neither produces a message. That is the most expensive green there is:
 * the user configured the tool, and the tool disagreed without saying so.
 *
 * ## Why this is its own trait
 *
 * ⚠️ It used to live inside {@see WritesReportOutput}, which meant it reached exactly the three
 * commands that write a report — and the machinery's own history says what that costs: "the
 * machinery for this existed and was tested from the day it was written; what it never had was a
 * caller." It then had three.
 *
 * The eight without it are the ones where it matters most. `predeploy` and `postdeploy` run INSIDE
 * the deploy window; `baseline`, `drift` and `format` write files into the repository; the MCP
 * server binds tools to whatever the configuration says. Two of them carry comments asserting the
 * validator has already refused the shape they are about to read — `PreflightService` justifies
 * falling back on an unusable threshold that way, and `McpCommand` says reaching a branch "means it
 * was bypassed". Neither sentence was true of the run.
 *
 * ## Self-sufficient on purpose
 *
 * It resolves its own translator and writes to its own stream rather than borrowing `stderr()` and
 * `translate()` from two other traits, which is how the previous arrangement ended up depending on
 * a method that lives somewhere else. A trait every command must use cannot also require two it
 * might not.
 *
 * ## Every violation, not the first
 *
 * The validator collects them all, deterministically. Reporting one at a time turns a config with
 * three typos into three round trips, and somebody stops after the first.
 */
trait ValidatesConfig
{
    /**
     * The call every command makes first: refuse the run when `config('sqlens')` is not a shape
     * this package understands.
     *
     * Called FIRST — before the reporter, before the profile, before anything opens a connection. A
     * misconfiguration that surfaces after twenty seconds of catalog reading is one people check
     * for less often.
     *
     * Reads the configuration itself rather than taking it as an argument, so the commands make ONE
     * call that cannot differ — some of them have a `Repository` in `handle()` and some do not, and
     * an argument would have meant a slightly different line in each.
     *
     * ⚠️ `sqlens:doctor` DOES NOT CALL THIS, and that is the one deliberate exception — see
     * {@see ConfigInspection()}.
     */
    private function refusesInvalidConfig(): bool
    {
        return ! $this->configIsValid($this->laravel->make(Repository::class)->get('sqlens'));
    }

    /**
     * The same inspection, handed back instead of acted on — for the one command that must survive
     * a configuration nothing else will run on.
     *
     * ⚠️ REFUSING IS THE WRONG ANSWER IN EXACTLY ONE PLACE, and it is the place people reach for
     * when something is wrong. `sqlens:doctor` exists to describe a broken environment; a doctor
     * that will not start because the configuration is broken has inverted its own purpose. Its
     * suite says so in an arm written long before this trait existed: "it DESCRIBES a broken
     * profile rather than dying on it — the one command that must survive it".
     *
     * So doctor REPORTS what the validator found and carries on. Nothing is lost by that: every
     * other command refuses on the same configuration, so a run that matters still stops — and the
     * command you then reach for is the one that can tell you which key it was.
     */
    private function configInspection(): ConfigInspection
    {
        return new ConfigValidator()->inspect($this->laravel->make(Repository::class)->get('sqlens'));
    }

    private function configIsValid(mixed $config): bool
    {
        $inspection = new ConfigValidator()->inspect($config);

        // The notices first, and they are printed whether or not the run goes on. A key that is
        // absent takes the shipped default — harmless for an upgrade, and exactly the state a
        // published config that dropped a section is in. Saying so once per key is what keeps the
        // leniency from being the silent kind.
        if ($inspection->notices !== []) {
            $this->configStream()->writeln($this->configMessage('sqlens::messages.commands.defaulted_config', [
                'count' => (string) count($inspection->notices),
            ]));

            foreach ($inspection->notices as $notice) {
                $this->configStream()->writeln('  '.$notice->message());
            }
        }

        if ($inspection->isValid()) {
            return true;
        }

        $this->configStream()->writeln($this->configMessage('sqlens::messages.commands.invalid_config', [
            'count' => (string) count($inspection->violations),
        ]));

        foreach ($inspection->violations as $violation) {
            $this->configStream()->writeln('  '.$violation->message());
        }

        return false;
    }

    /**
     * The error stream, never the report stream.
     *
     * A `--format=json > report.json` has to yield a JSON file even on a run that refused: a shell
     * redirect that captured a configuration error as if it were the report would corrupt whatever
     * consumes it.
     */
    private function configStream(): OutputInterface
    {
        return $this->output->getErrorStyle();
    }

    /**
     * The shipped locale, deliberately, not the application's.
     *
     * A project running under a locale this package does not ship would otherwise read the
     * translation KEY where a sentence belongs — while being told its configuration is wrong.
     *
     * @param  array<string, string|int>  $replace
     */
    private function configMessage(string $key, array $replace = []): string
    {
        return (string) $this->laravel->make(Translator::class)->get($key, $replace, ShippedLocale::CODE);
    }
}
