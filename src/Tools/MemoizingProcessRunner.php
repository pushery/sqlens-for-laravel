<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

/**
 * A {@see ProcessRunner} that remembers the answers which cannot change during a run, and passes
 * the actual work straight through.
 *
 * ## What is cached, and why exactly those two
 *
 * `locate()` and `version()` answer questions about the MACHINE: where a binary lives, and which
 * build it is. Neither depends on the input, so both give the same answer for the first file and
 * the two-hundredth. `run()` is the work itself and is never cached — an answer that depended on
 * the SQL and came back from a cache would be catastrophic in a suite that WRITES FILES.
 *
 * ## The measurement that made this exist
 *
 * `ExternalSqlFormatter::format()` located the binary and probed its version on every call, so a
 * repository-wide run paid both per `.sql` file. Measured with a counting runner: **25 locate calls
 * and 25 version probes for 25 files**, growing in exact proportion to the project.
 *
 * The version probe is the expensive half — it is a fork, an exec, a dynamic link and an exit, for
 * a string already held. Two hundred files meant two hundred processes to be told the same thing,
 * and that is the difference between a pre-commit hook somebody keeps and one they delete.
 *
 * ## It also makes a promise the reporter already relies on
 *
 * `sqlens:format` prints ONE backend version for the whole run and takes it from a result rather
 * than probing separately, precisely so it cannot name a binary other than the one that did the
 * work. Re-resolving per file leaves a window where file 40 is formatted by something file 39 was
 * not, and nothing in the report would say so. Remembering the first answer closes it.
 *
 * ## Absence is an ANSWER, and it is remembered too
 *
 * `locate()` returns null for a binary that is not installed, and that is the ordinary state of a
 * machine that never installed it — the case a repository-wide run hits most. A cache that treated
 * null as "not asked yet" would look again for every file and cache nothing at all in exactly the
 * situation it exists for. Hence the separate "asked" set rather than a null check.
 */
final class MemoizingProcessRunner implements ProcessRunner
{
    /** @var array<string, string|null> */
    private array $located = [];

    /** @var array<string, string|null> */
    private array $versions = [];

    public function __construct(private readonly ProcessRunner $inner) {}

    public function locate(string $binaryName): ?string
    {
        if (! array_key_exists($binaryName, $this->located)) {
            $this->located[$binaryName] = $this->inner->locate($binaryName);
        }

        return $this->located[$binaryName];
    }

    public function version(string $binaryPath): ?string
    {
        if (! array_key_exists($binaryPath, $this->versions)) {
            $this->versions[$binaryPath] = $this->inner->version($binaryPath);
        }

        return $this->versions[$binaryPath];
    }

    /**
     * Straight through, always.
     *
     * Keyed on nothing and remembered nowhere: the result depends on the SQL, the arguments and the
     * state of the machine at that moment, and this package's one writing suite puts the answer
     * into a file.
     */
    public function run(string $binaryPath, array $arguments, float $timeoutSeconds, ?string $stdin = null, array $environment = []): ToolRunResult
    {
        return $this->inner->run($binaryPath, $arguments, $timeoutSeconds, $stdin, $environment);
    }
}
