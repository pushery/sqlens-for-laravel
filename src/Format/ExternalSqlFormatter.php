<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

use Pushery\SQLens\Contracts\SqlFormatter;
use Pushery\SQLens\Tools\ProcessRunner;
use Pushery\SQLens\Tools\ToolRunOutcome;
use Pushery\SQLens\Tools\ToolRunResult;

/**
 * The shared half of every external formatter backend: run a binary, and never let it take the run
 * with it.
 *
 * ## Why one base rather than two adapters
 *
 * pgFormatter and SQLFluff differ in their command line, their dialect coverage and the style
 * options they can express. They do NOT differ in any of the things that are hard: bounding the
 * process, treating a missing binary as a named reason rather than an exception, refusing a version
 * outside the measured window, and passing the tool's own words through instead of interpreting
 * them. Two copies of that would be two chances to get the hard part wrong, and the second copy is
 * always the one that forgets the timeout.
 *
 * ## Every failure is a REASON, never a throw
 *
 * A missing binary is the ordinary state of a machine that never installed it, and a suite
 * formatting a hundred files must report the two it could not rather than dying on the third. The
 * base turns each failure into a {@see FormatResult::undetermined()} with the tool's own output
 * attached — passed through rather than paraphrased, because a paraphrase is a second opinion about
 * a message the tool's authors wrote deliberately.
 */
abstract readonly class ExternalSqlFormatter implements SqlFormatter
{
    /**
     * @param  string  $binary  the executable, resolved from configuration or found on PATH
     * @param  int  $timeoutSeconds  a bound, not a suggestion — a formatter without one holds a CI
     *                               step and the whole shared queue behind it for as long as it stands
     */
    public function __construct(
        protected ProcessRunner $processes,
        protected string $binary,
        protected int $timeoutSeconds = 15,
    ) {}

    public function isAvailable(): bool
    {
        return $this->processes->locate($this->binary) !== null;
    }

    /**
     * The installed version, probed directly rather than harvested from a run.
     *
     * Located first: probing a path that does not exist would spend a process to learn what
     * `locate()` already knows. Both calls go through the memoizing runner, so asking N times across
     * a repository costs one lookup and one probe -- the cap ExternalFormatterProcessBudgetTest
     * holds for `format()` covers this for the same reason, because it is the same runner.
     */
    public function version(): ?string
    {
        $path = $this->processes->locate($this->binary);

        return $path === null ? null : $this->processes->version($path);
    }

    public function format(string $sql, Dialect $dialect, FormatStyle $style): FormatResult
    {
        if (! $this->supports($dialect)) {
            return FormatResult::undetermined(
                FormatUndeterminedReason::DialectUnsupported,
                $this->name(),
                $dialect,
                $style,
                'this backend does not handle '.$dialect->value,
            );
        }

        $unexpressible = $this->unexpressible($style);

        if ($unexpressible !== []) {
            // REPORTED, never silently dropped. A backend that quietly ignored `leading_commas`
            // would produce output the project did not ask for and no signal that it had happened —
            // and the next run would rewrite every file again, forever.
            return FormatResult::undetermined(
                FormatUndeterminedReason::StyleNotExpressible,
                $this->name(),
                $dialect,
                $style,
                'this backend cannot express: '.implode(', ', $unexpressible),
            );
        }

        // Located BEFORE it is run, so "not installed" is a different answer from "ran and failed".
        // A caller told the second when the first is true goes looking for a bug in their SQL.
        $path = $this->processes->locate($this->binary);

        if ($path === null) {
            return FormatResult::undetermined(
                FormatUndeterminedReason::ToolMissing,
                $this->name(),
                $dialect,
                $style,
                sprintf('`%s` is not on the search path; install it or set its path in the format config', $this->binary),
            );
        }

        $run = $this->processes->run(
            $path,
            $this->arguments($dialect, $style),
            $this->timeoutSeconds,
            // On STDIN rather than in a temp file. A file is a side effect: it needs a location, a
            // cleanup path that also runs when the run fails, and it puts a machine-specific
            // absolute path into whatever the tool reports back.
            $this->input($sql, $dialect, $style),
        );

        if ($run->outcome === ToolRunOutcome::TimedOut) {
            return FormatResult::undetermined(
                FormatUndeterminedReason::ToolTimedOut,
                $this->name(),
                $dialect,
                $style,
                sprintf('the formatter did not finish within %d seconds', $this->timeoutSeconds),
            );
        }

        if ($run->outcome === ToolRunOutcome::StartFailed) {
            return FormatResult::undetermined(
                FormatUndeterminedReason::ToolMissing,
                $this->name(),
                $dialect,
                $style,
                sprintf('`%s` is on the path and could not be started — check that it is executable', $path),
            );
        }

        if (! $this->completed($run)) {
            return FormatResult::undetermined(
                FormatUndeterminedReason::ToolRefused,
                $this->name(),
                $dialect,
                $style,
                // The tool's OWN words. A paraphrase is a second opinion about a message its authors
                // wrote deliberately, and it is the paraphrase that goes stale when they improve it.
                trim($run->stderrExcerpt) !== '' ? trim($run->stderrExcerpt) : 'exit code '.$run->exitCode,
            );
        }

        $formatted = $this->output($run->stdout, $dialect, $style);

        if ($formatted === null) {
            return FormatResult::undetermined(
                FormatUndeterminedReason::ToolOutputRejected,
                $this->name(),
                $dialect,
                $style,
                'the formatter did not hand the statement back in the shape it was given, so its output is not used',
            );
        }

        // Exit 0 is the tool's claim that it formatted, not proof that it kept the statement. Both
        // external backends were measured writing a different one (see StatementIdentity), and what
        // passes here is what lands in the file.
        $changed = StatementIdentity::firstDifference($sql, $formatted, $dialect);

        if ($changed !== null) {
            return FormatResult::undetermined(
                FormatUndeterminedReason::ToolOutputRejected,
                $this->name(),
                $dialect,
                $style,
                sprintf('the output no longer reads as the same statement, so it is not used: %s', $changed),
            );
        }

        return FormatResult::formatted($formatted, $this->name(), $dialect, $style, $this->processes->version($path));
    }

    /**
     * Whether a finished run carries a formatted statement. Exit 0, unless a backend knows better.
     */
    protected function completed(ToolRunResult $run): bool
    {
        return $run->exitCode === 0;
    }

    /**
     * What the tool reads on STDIN: the statement, unless a backend has to carry a setting inside it.
     *
     * A backend whose command line cannot express a style value may still accept it in the text, the
     * way SQLFluff reads configuration from a comment. Kept beside {@see self::output()}, because
     * whatever goes in this way has to come back out before the result is used.
     */
    protected function input(string $sql, Dialect $dialect, FormatStyle $style): string
    {
        return $sql;
    }

    /**
     * The formatted statement taken back out of what the tool wrote, or null when that output is not
     * the statement it was handed.
     */
    protected function output(string $stdout, Dialect $dialect, FormatStyle $style): ?string
    {
        return $stdout;
    }

    /**
     * The command-line arguments for this backend.
     *
     * @return list<string>
     */
    abstract protected function arguments(Dialect $dialect, FormatStyle $style): array;

    /**
     * Style options this backend cannot express, by name.
     *
     * Answered UP FRONT rather than discovered from the output, because the alternative is comparing
     * what came back against what was asked for — which is guessing, and guesses about formatting
     * are how a `--check` run reports a clean file as dirty.
     *
     * @return list<string>
     */
    abstract public function unexpressible(FormatStyle $style): array;
}
