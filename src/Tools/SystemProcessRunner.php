<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

use Pushery\SQLens\Findings\CredentialRedactor;
use Symfony\Component\Process\Exception\ProcessTimedOutException;
use Symfony\Component\Process\Process;
use Throwable;

/**
 * The real process runner: it searches the system `$PATH` for a binary and runs it
 * with `--version`. It never reaches the network — it only inspects `$PATH` entries on
 * disk and runs a LOCAL executable, with a bounded timeout so a version probe can
 * never hang a lint run.
 */
final readonly class SystemProcessRunner implements ProcessRunner
{
    /** A version probe is bounded — the run is never held hostage to a slow binary. */
    public const float PROBE_TIMEOUT_SECONDS = 5.0;

    /**
     * @param  float  $timeoutSeconds  the probe bound; the shipped default is the only value the
     *                                 package ever uses, and a test pins that. It is a parameter so
     *                                 the timeout BEHAVIOR can be driven without a five-second wait —
     *                                 what happens when the bound is hit is identical at 0.2 s and
     *                                 at 5 s, so nothing about the tested path is a configuration
     *                                 production does not have.
     */
    public function __construct(private float $timeoutSeconds = self::PROBE_TIMEOUT_SECONDS) {}

    public function locate(string $binaryName): ?string
    {
        // ⚠️ A PINNED PATH IS NOT A NAME, AND THIS METHOD USED TO TREAT IT AS ONE.
        //
        // Everything below joins the argument onto each `$PATH` directory, which is right for a
        // bare `pg_format` and nonsense for `/opt/homebrew/bin/pg_format`: the join produces
        // `/usr/bin//opt/homebrew/bin/pg_format`, no candidate exists, and the method answers
        // null. Measured — `locate('php')` resolves and `locate('<that same absolute path>')`
        // returns null.
        //
        // The consequence is the one the shipped config explicitly promises against. Its `tools`
        // section says: "A pinned path that does not run is REPORTED — never quietly replaced by
        // whatever else is installed, because naming a path is a statement about which binary
        // produced the verdict." The pin was silently replaced by whatever the backend's default
        // name found on `$PATH`, or by the built-in fallback — so a project that pinned one
        // formatter got a verdict from another, with nothing in the report saying so.
        //
        // A path is anything carrying a separator, not merely one that is absolute: `./bin/tool`
        // and `vendor/bin/tool` are addresses too, and joining either onto `$PATH` is the same
        // category error. Both are answered here, and a pin that does not resolve returns null —
        // which every caller already reports as a NAMED missing tool rather than a fallback.
        if (str_contains($binaryName, DIRECTORY_SEPARATOR)) {
            return is_file($binaryName) && is_executable($binaryName) ? $binaryName : null;
        }

        foreach ($this->pathDirectories() as $directory) {
            $candidate = rtrim($directory, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR.$binaryName;

            if (is_file($candidate) && is_executable($candidate)) {
                return $candidate;
            }
        }

        return null;
    }

    public function version(string $binaryPath): ?string
    {
        $process = new Process([$binaryPath, '--version']);
        $process->setTimeout($this->timeoutSeconds);

        try {
            $process->run();
        } catch (Throwable) {
            // A probe that hits its bound THROWS — `run()` does not merely return an unsuccessful
            // status for a timeout, which is what the previous comment here assumed. That made the
            // one thing the bound exists for, a binary that hangs, the one thing that took the run
            // down with it: `ToolLocator` calls this while resolving tools, so an uncaught timeout
            // ended `sqlens:doctor` and every lint run that probed a tool.
            //
            // A binary probed defensively is by definition one nothing is known about yet. It may
            // hang, it may not be a program at all — none of that is an exceptional situation here,
            // it is the situation. So it answers null: the version could not be established.
            return null;
        }

        // A binary that cannot be launched or that exits non-zero is likewise a null version, never
        // a crash.
        if (! $process->isSuccessful()) {
            return null;
        }

        $lines = explode("\n", trim($process->getOutput()));

        return trim($lines[0]);
    }

    /**
     * How much stderr travels with a result.
     *
     * Bounded because a tool that goes wrong can produce megabytes, and every byte of it ends
     * up wherever the result does — a finding, a report, a CI log that outlives the run. The
     * first part is where a tool says what it could not do; the rest is repetition.
     */
    public const int STDERR_EXCERPT_BYTES = 2000;

    /** POSIX: the file was found and could not be executed. */
    private const int EXIT_NOT_EXECUTABLE = 126;

    /** POSIX: the command was not found at all. */
    private const int EXIT_NOT_FOUND = 127;

    /**
     * The environment a tool is allowed to inherit.
     *
     * An ALLOWLIST, not a denylist, and that direction is the point: a tool that inherits the
     * shell inherits `PGHOST`, `PGPASSWORD`, `DATABASE_URL` and everything else that happens to
     * be exported — which can send a linter to a live database, and would make the result
     * depend on whose terminal it started in. Naming what may pass through means a variable
     * added to the fleet tomorrow is excluded by default rather than included by accident.
     *
     * `PATH` so the binary can find its own helpers, `HOME` and the temp vars because tools
     * write scratch files. Nothing about a database.
     */
    private const array INHERITED_ENVIRONMENT = ['PATH', 'HOME', 'TMPDIR', 'TMP', 'TEMP'];

    public function run(string $binaryPath, array $arguments, float $timeoutSeconds, ?string $stdin = null, array $environment = []): ToolRunResult
    {
        $process = new Process([$binaryPath, ...$arguments], null, $this->childEnvironment($environment));
        $process->setTimeout($timeoutSeconds);

        if ($stdin !== null) {
            $process->setInput($stdin);
        }

        try {
            $process->run();
        } catch (ProcessTimedOutException) {
            // The bound was hit. Nothing was measured, and saying so is the whole reason this
            // outcome is separate from a non-zero exit: both look like failure, only one of them
            // ran to a verdict.
            return new ToolRunResult(
                ToolRunOutcome::TimedOut,
                ToolRunResult::NO_EXIT_CODE,
                '',
                $this->excerpt($process->getErrorOutput()),
            );
        }

        $exitCode = $process->getExitCode() ?? ToolRunResult::NO_EXIT_CODE;

        // A binary that could not be started reports itself through the exit code rather than an
        // exception — measured, not assumed: a non-executable file and a path that does not exist
        // both come back as 126 here, with no throw at all. 126 and 127 are POSIX-reserved for
        // exactly this ("found but not executable", "not found"), so they are the start failure,
        // not a verdict. Reading them as a tool's own answer would turn "the tool never ran" into
        // "the tool ran and was unhappy" — the collapse this outcome exists to prevent.
        if ($exitCode === self::EXIT_NOT_EXECUTABLE || $exitCode === self::EXIT_NOT_FOUND) {
            return new ToolRunResult(
                ToolRunOutcome::StartFailed,
                $exitCode,
                '',
                $this->excerpt($process->getErrorOutput()),
            );
        }

        // Otherwise the exit code travels unchanged. A linter that finds problems exits non-zero
        // and has completed perfectly well; deciding what the number means is the caller's job.
        return new ToolRunResult(
            ToolRunOutcome::Completed,
            $exitCode,
            $process->getOutput(),
            $this->excerpt($process->getErrorOutput()),
        );
    }

    /**
     * The child environment: the allowlisted variables, what the caller passed explicitly, and a
     * forced C locale.
     *
     * The locale is forced rather than inherited because a tool that formats numbers or sorts
     * output by locale gives a different answer on a German laptop than in a container — a
     * determinism break that is invisible until two people compare reports.
     *
     * ## Why explicit variables are allowed where inherited ones are not
     *
     * The allowlist exists so a tool cannot pick up `PGHOST` or `PGPASSWORD` from whichever shell
     * happened to start the run. That rule is about INHERITANCE, and it stays absolute. But one
     * adapter — the Postgres Language Server's — has to send its tool to a database on purpose,
     * and the only safe way to do that is for the caller to state which one: the credentials come
     * from the connection SQLens was asked to audit, never from the ambient environment. So the
     * caller may NAME variables, and nothing is ever inherited that was not named.
     *
     * The difference is not cosmetic. Inherited, the answer depends on whose terminal started the
     * run; named, it depends on the configuration under audit, which is the thing being measured.
     *
     * @param  array<string, string>  $explicit  variables the CALLER states, never inherited
     * @return array<string, string|false>
     */
    private function childEnvironment(array $explicit): array
    {
        $environment = [];

        foreach (self::INHERITED_ENVIRONMENT as $name) {
            $value = getenv($name);

            if (is_string($value)) {
                $environment[$name] = $value;
            }
        }

        $environment = [...$environment, ...$explicit];

        // The locale is forced AFTER the caller's variables rather than before, so a caller cannot
        // set it — deliberately. Every other variable here is the caller's business; determinism
        // is not, and an adapter that could quietly re-localize its tool would be able to change
        // what a report says without changing what it checked.
        $environment['LC_ALL'] = 'C';
        $environment['LANG'] = 'C';

        // Everything else is REMOVED rather than left alone. Symfony merges what it is given
        // with the parent environment, so an allowlist only becomes one when the remainder is
        // explicitly unset — `false` is Symfony's "delete this variable".
        foreach (array_keys(getenv()) as $name) {
            if (! array_key_exists($name, $environment)) {
                $environment[$name] = false;
            }
        }

        return $environment;
    }

    /** A bounded, credential-free slice of a tool's own complaints. */
    private function excerpt(string $stderr): string
    {
        $trimmed = trim($stderr);

        if ($trimmed === '') {
            return '';
        }

        return new CredentialRedactor()->redact(mb_strcut($trimmed, 0, self::STDERR_EXCERPT_BYTES));
    }

    /**
     * The `$PATH` entries, empty segments dropped. An unset PATH coerces to an empty
     * string and yields no directories, so a locate simply finds nothing.
     *
     * @return list<string>
     */
    private function pathDirectories(): array
    {
        return array_values(array_filter(
            explode(PATH_SEPARATOR, (string) getenv('PATH')),
            static fn (string $directory): bool => $directory !== '',
        ));
    }
}
