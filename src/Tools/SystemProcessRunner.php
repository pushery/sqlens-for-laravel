<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

use Closure;
use Override;
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
     * @param  string  $osFamily  the platform whose process table a stopped tool's descendants are
     *                            read from. A parameter only so every way of reading it can be
     *                            driven on one machine; production never passes anything but the
     *                            default, and a test pins that.
     */
    public function __construct(
        private float $timeoutSeconds = self::PROBE_TIMEOUT_SECONDS,
        private string $osFamily = PHP_OS_FAMILY,
    ) {}

    public function locate(string $binaryName): ?string
    {
        // A pinned path is not a name.
        //
        // Everything below joins the argument onto each `$PATH` directory, which is right for a
        // bare `pg_format` and nonsense for `/opt/homebrew/bin/pg_format`: the join produces
        // `/usr/bin//opt/homebrew/bin/pg_format`, no candidate exists, and the method would answer
        // null.
        //
        // The consequence would be the one the shipped config explicitly promises against. Its
        // `tools` section says: "A pinned path that does not run is REPORTED — never quietly
        // replaced by whatever else is installed, because naming a path is a statement about which
        // binary produced the verdict." A pin lost that way would be replaced by whatever the
        // backend's default name finds on `$PATH`, or by the built-in fallback — so a project that
        // pinned one formatter would get a verdict from another, with nothing in the report saying so.
        //
        // A path is anything carrying a separator, not merely one that is absolute: `./bin/tool`
        // and `vendor/bin/tool` are addresses too, and joining either onto `$PATH` is the same
        // category error. Both are answered here, and a pin that does not resolve returns null —
        // which every caller already reports as a named missing tool rather than a fallback.
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
        // The same allowlisted environment as a run. A probe is the first time a binary nothing is
        // known about yet is started, which is the worst moment to hand it the whole shell, and its
        // answer is parsed, which is why it needs the C locale as much as a run does.
        $process = $this->process([$binaryPath, '--version'], $this->childEnvironment([]));
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
        $process = $this->process([$binaryPath, ...$arguments], $this->childEnvironment($environment));
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
     * A process whose stop takes every process it started down with it.
     *
     * Symfony stops a process by signaling the pid it started, and only that pid. A tool installed
     * through npm is not the program it names: `postgrestools` on the path is a node launcher that
     * runs the native binary as its child and waits for it. Measured with the launcher the npm
     * package installs, a three-second bound and a database that stopped answering after the
     * startup: the timeout ended the launcher, and the native binary went on as an orphan of init,
     * holding ten database sessions open after the run had reported that nothing was measured.
     * Called directly, the same binary left nothing behind.
     *
     * So the descendants are read before Symfony sends its signal, while the tool still links them
     * to this run, and killed first. Symfony then stops the tool itself as it always did.
     *
     * @param  list<string>  $command
     * @param  array<string, string|false>|null  $environment
     */
    private function process(array $command, ?array $environment = null): Process
    {
        return new class($command, $environment, $this->stopDescendants(...)) extends Process
        {
            /**
             * @param  list<string>  $command
             * @param  array<string, string|false>|null  $environment
             * @param  Closure(int): void  $beforeStop
             */
            public function __construct(array $command, ?array $environment, private readonly Closure $beforeStop)
            {
                parent::__construct($command, null, $environment);
            }

            #[Override]
            public function stop(float $timeout = 10, ?int $signal = null): ?int
            {
                $pid = $this->isRunning() ? $this->getPid() : null;

                if ($pid !== null) {
                    ($this->beforeStop)($pid);
                }

                return parent::stop($timeout, $signal);
            }
        };
    }

    /**
     * Kill every process below `$pid`, read while `$pid` still links them to this run.
     *
     * Killed outright, the way Symfony ends a process that outlives its stop window. The `kill` is
     * the shell's own, because a container without procps has no `kill` binary but always a shell.
     */
    private function stopDescendants(int $pid): void
    {
        $descendants = array_diff($this->processTable()->descendantsOf($pid), [getmypid()]);

        if ($descendants !== []) {
            new Process(['/bin/sh', '-c', 'kill -KILL "$@" 2>/dev/null', 'sh', ...array_map(strval(...), $descendants)])->run();
        }
    }

    /** The process table of this platform, read the way the platform publishes it. */
    private function processTable(): ProcessTable
    {
        return match ($this->osFamily) {
            'Linux' => ProcessTable::fromProc('/proc'),
            // Symfony stops a whole tree there already, through `taskkill /T`.
            'Windows' => ProcessTable::empty(),
            default => ProcessTable::fromPsOutput($this->processList()),
        };
    }

    /** What `ps` prints about every process, or nothing where there is no `ps` to ask. */
    private function processList(): string
    {
        $ps = new Process(['ps', '-A', '-o', 'pid=', '-o', 'ppid=']);
        $ps->run();

        return $ps->getOutput();
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
        //
        // The parent environment Symfony merges is `$_ENV` as well as `getenv()`, so both are
        // walked. A variable that lives only in `$_ENV` is the shape Laravel loads `.env` in once
        // putenv is disabled, and it carried `DB_PASSWORD` and `APP_KEY` into every tool.
        foreach (array_keys([...getenv(), ...$_ENV]) as $name) {
            if (is_string($name) && ! array_key_exists($name, $environment)) {
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
     * The ABSOLUTE `$PATH` entries. An unset PATH coerces to an empty string and yields no
     * directories, so a locate simply finds nothing.
     *
     * **A relative entry is dropped, and that is a credential boundary rather than tidiness.**
     * Joined like any other directory, `.`, `node_modules/.bin` and `vendor/bin` would be CWE-427,
     * an uncontrolled search path element: whatever the process happens to be sitting in would
     * decide which binary runs.
     *
     * The version fence does not close it: `ToolLocator` compares a `--version` string and
     * authenticates nothing, so any binary printing the expected line passes.
     *
     * And one tool makes this concrete. `pgls` is the only adapter handed the audited connection's
     * password — it goes out as `PGPASSWORD` — and it ships enabled with `path => null`, resolved
     * through `$PATH`. So the first `postgrestools` on the search path receives the database
     * password, and without this filter a `.` entry would make "the first one" mean "whatever is in
     * this directory".
     *
     * Absoluteness is tested the way {@see SingleFileResolver::absolutePath()} already tests it in
     * this package, rather than with a second spelling of the same question.
     *
     * @return list<string>
     */
    private function pathDirectories(): array
    {
        return array_values(array_filter(
            explode(PATH_SEPARATOR, (string) getenv('PATH')),
            static fn (string $directory): bool => str_starts_with($directory, '/')
                || preg_match('#^[A-Za-z]:[\\\\/]#', $directory) === 1,
        ));
    }
}
