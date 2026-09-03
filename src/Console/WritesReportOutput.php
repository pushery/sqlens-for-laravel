<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Pushery\SQLens\Config\ConfigValidator;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Output\StreamOutput;

/**
 * Where a command's report goes, and whether it should run at all — shared by every suite command.
 *
 * Split out of {@see SharesRunOptions} rather than left in it, because that trait had the wrong
 * granularity and said so itself. It bundles this output plumbing with the validators for
 * `--level`, `--category` and `--min-severity`, and a command that offers `--output` but not
 * `--level` could therefore not use it: Larastan resolves an option access against the command's
 * real signature and reports `Command "sqlens:security" does not have option "level"`. So
 * `sqlens:security` carried byte-identical private copies of two of these methods, with a note
 * saying they would come home when its flags arrived. They have.
 *
 * The line between the two traits is what a method DEPENDS on. Everything here needs only
 * `--output` and the configuration, which every suite command has. Everything left behind needs a
 * flag that narrows a run, which they do not all offer — `sqlens:security` deliberately has no
 * `--level`, because a security finding is weighed on the severity axis and a level would let a
 * project's strictness appetite silently withhold a security rule.
 */
trait WritesReportOutput
{
    /**
     * Whether `config('sqlens')` is a configuration this package understands.
     *
     * ## The failure this exists to stop
     *
     * A key the package does not know is a key the package IGNORES, and ignoring is silent. A run
     * with `levl: 3` uses the default level and comes back green because it checked less. A run
     * with `audit.tenancy.mode: 'explicits'` compares unequal to `'explicit'`, falls into the
     * signal branch, and behaves as if the project had declared no reference tenant at all — while
     * the project believes it declared one. Neither produces a message. That is the most expensive
     * green there is: the user configured the tool, and the tool disagreed without saying so.
     *
     * ## Why HERE, and why first
     *
     * In the shared trait rather than in each command, because two copies would eventually
     * disagree about what "before the first check" means, and each command's own test would still
     * pass. Before the reporter, before the profile, before anything opens a connection — the same
     * rule the ignore-list validator and the tenancy guard follow. A misconfiguration that surfaces
     * after twenty seconds of catalog reading is one people check for less often.
     *
     * It must also run before {@see ResolvesProfile}, whose docblock states that the validator has
     * already rejected an unknown profile. That sentence was true of the design and false of the
     * run: nothing called the validator at all.
     *
     * ## Every violation, not the first
     *
     * The validator already collects them all, deterministically. Reporting one at a time turns a
     * config with three typos into three round trips, and somebody stops after the first.
     */
    private function configIsValid(mixed $config): bool
    {
        $inspection = new ConfigValidator()->inspect($config);

        // The notices first, and they are printed whether or not the run goes on. A key that is
        // absent takes the shipped default — harmless for an upgrade, and exactly
        // the state a published config that dropped a section is in. Saying so once per key is
        // what keeps the leniency from being the silent kind.
        if ($inspection->notices !== []) {
            $this->stderr()->writeln($this->translate('sqlens::messages.commands.defaulted_config', [
                'count' => (string) count($inspection->notices),
            ]));

            foreach ($inspection->notices as $notice) {
                $this->stderr()->writeln('  '.$notice->message());
            }
        }

        if ($inspection->isValid()) {
            return true;
        }

        $this->stderr()->writeln($this->translate('sqlens::messages.commands.invalid_config', [
            'count' => (string) count($inspection->violations),
        ]));

        foreach ($inspection->violations as $violation) {
            $this->stderr()->writeln('  '.$violation->message());
        }

        return false;
    }

    /** The stream the report is written to, or null when `--output` names a path that cannot be opened. */
    private function reportOutput(): ?OutputInterface
    {
        $file = $this->option('output');

        if (! is_string($file) || $file === '') {
            return $this->output->getOutput();
        }

        $handle = @fopen($file, 'w');

        if ($handle === false) {
            $this->stderr()->writeln($this->translate('sqlens::messages.commands.output_unwritable', ['file' => $file]));

            return null;
        }

        return new StreamOutput($handle);
    }

    /** Close an `--output` stream this command opened — never the console's own. */
    private function closeReportOutput(OutputInterface $output): void
    {
        if (! $output instanceof StreamOutput || $output === $this->output->getOutput()) {
            return;
        }

        $handle = $output->getStream();

        if (is_resource($handle)) {
            fclose($handle);
        }
    }

    /**
     * Close an `--output` file this command opened but never wrote a report into, and remove it.
     *
     * `--output` is opened with `w` before the run, which is what proves the path is
     * writable without costing a connection to discover — and it truncates the file at that
     * instant. Every path that then returned without reporting left a ZERO-BYTE file behind, and a
     * zero-byte report is worse than none: `test -f report.json` passes, a consumer that reads an
     * empty findings list as "clean" agrees, and the run that produced it never looked at a
     * database. The test covering this even asserted "no report file at all" while a file was
     * sitting there.
     *
     * Called from a `finally`, never from the individual return sites. There are a dozen of those
     * and a thirteenth arrives with the next option; remembering to clean up at each one is exactly
     * the kind of discipline that holds until it does not.
     */
    private function discardReportOutput(OutputInterface $output): void
    {
        if (! $output instanceof StreamOutput || $output === $this->output->getOutput()) {
            return;
        }

        $handle = $output->getStream();
        $path = is_resource($handle) ? (stream_get_meta_data($handle)['uri'] ?? null) : null;

        $this->closeReportOutput($output);

        if (is_string($path) && is_file($path)) {
            @unlink($path);
        }
    }

    /**
     * Errors go to STDERR, the report to STDOUT.
     *
     * So `--format=json > report.json` yields a JSON file even on a run that failed: a shell
     * redirect that captured an error message as if it were the report would corrupt whatever
     * consumes it.
     */
    private function stderr(): OutputInterface
    {
        return $this->output->getErrorStyle();
    }
}
