<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Pgls;

use JsonException;
use Pushery\SQLens\Tools\ProcessRunner;
use Pushery\SQLens\Tools\ToolRunOutcome;
use Pushery\SQLens\Tools\ToolRunResult;

/**
 * Runs the Postgres Language Server's `dblint` against a database and reads its report.
 *
 * Nothing here throws. An amplifier that is asked a question must never be able to end the run
 * that asked it, so every way this can go wrong ends as a named reason.
 *
 * ## What it does to the database, measured
 *
 * This is the one adapter in the package whose tool opens its own connection, so the question
 * "does it harm anything" could not be reasoned about — it was measured, with `log_statement='all'`
 * on a probe database. A run issues **sixteen statements, zero of them mutating and zero taking a
 * lock**: catalog reads, inside one transaction, with `set local search_path = ''`.
 *
 * That measurement is what makes this adapter defensible under "primum non nocere", and it is a
 * property of somebody else's binary rather than of this code — which is exactly why the
 * real-binary lane re-measures it rather than trusting this paragraph.
 *
 * ## Why it hands the tool a configuration file
 *
 * Not for safety. Measured: a default `dblint` run issues the same sixteen read-only statements,
 * so `typecheck` and `plpgsql_check` add nothing at the database for this subcommand.
 *
 * The reason is suppression. A `postgres-language-server.jsonc` sitting in the working directory
 * IS read and DOES change the result — measured: one finding became zero, with nothing anywhere
 * saying so. Since SQLens maps this tool's output into its own report, such a file would silence a
 * SQLens finding without passing through the baseline or the ignore list, which are the two places
 * a suppression is supposed to be visible.
 *
 * Squawk's answer to the same problem — point the tool at the null device — does not work here:
 * `--config-path` is read as a DIRECTORY when it names one, so `/dev/null` sends the tool looking
 * for `/dev/null/postgres-language-server.jsonc`. It accepts a FILE path under any name, though,
 * so the package ships one. No temporary file, therefore no cleanup path that also has to run when
 * the run fails, and the configuration is versioned alongside the code that depends on it.
 */
final readonly class PglsRunner
{
    /** The subcommand that lints a database schema, as opposed to a directory of SQL files. */
    private const string SUBCOMMAND = 'dblint';

    /** The shipped configuration that neutralizes whatever the project has in its working directory. */
    public const string NEUTRAL_CONFIG_FILE = 'resources/data/pgls-neutral.json';

    /**
     * The exit codes the tool's contract uses: nothing found, and something found.
     *
     * Measured, and the second one is doing more work than it looks: a connection failure ALSO
     * exits 1, with plain text where the report should be. So the exit code alone cannot separate
     * "found problems" from "never got there" — {@see read()} does that on the output instead.
     */
    private const array CONTRACT_EXIT_CODES = [0, 1];

    public function __construct(private ProcessRunner $runner, private string $packageRoot) {}

    /**
     * Lint one database and read what comes back.
     *
     * @param  string  $binaryPath  the binary the locator resolved and the version gate accepted
     */
    public function run(string $binaryPath, PglsInvocation $invocation): PglsRunResult
    {
        $result = $this->runner->run(
            $binaryPath,
            $this->arguments($invocation->connection),
            $invocation->timeoutSeconds,
            null,
            // The password, and nothing else. Everything the child gets is named here rather than
            // inherited, so the tool cannot pick up a `PGHOST` from whichever shell started the
            // run and quietly audit a different server than the one under audit.
            $invocation->connection->environment(),
        );

        if ($result->outcome !== ToolRunOutcome::Completed) {
            return PglsRunResult::failed(PglsFailureReason::RunFailed, $this->outcomeDetail($result));
        }

        if (! in_array($result->exitCode, self::CONTRACT_EXIT_CODES, true)) {
            return PglsRunResult::failed(
                PglsFailureReason::RunFailed,
                sprintf('postgrestools exited %d, which is not part of its exit-code contract%s', $result->exitCode, $this->stderrSuffix($result)),
            );
        }

        return $this->read($result, $invocation->connection);
    }

    /**
     * The argv, in a fixed order.
     *
     * Fixed because determinism reaches this far down: two runs against the same database must
     * send the same bytes to the same program, so a report can be compared with the one before it.
     *
     * The password is conspicuously absent. It goes in the environment — an argument list is
     * readable by every user on the machine through `ps`, for as long as the process lives.
     *
     * @return list<string>
     */
    private function arguments(PglsConnection $connection): array
    {
        return [
            self::SUBCOMMAND,
            '--config-path='.$this->packageRoot.'/'.self::NEUTRAL_CONFIG_FILE,
            '--host='.$connection->host,
            '--port='.$connection->port,
            '--username='.$connection->username,
            '--database='.$connection->database,
            '--reporter=json',
            // Without this the tool caps the report at twenty and says nothing about the rest, so a
            // schema with twenty-one problems would report twenty and read as complete.
            '--max-diagnostics=none',
        ];
    }

    /** Read the report, or say which way it was not one. */
    private function read(ToolRunResult $result, PglsConnection $connection): PglsRunResult
    {
        try {
            $decoded = json_decode($result->stdout, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            // Measured: this is how a connection failure ARRIVES. An unreachable host, a missing
            // database and an unknown role all exit 1 and write plain text, even though
            // `--reporter=json` was asked for. So "the output is not JSON" is not evidence of a
            // broken tool here — it is the ordinary shape of the most likely misconfiguration, and
            // reporting it as a defect in the tool would send the reader to the wrong place.
            return PglsRunResult::failed(
                PglsFailureReason::DatabaseUnreachable,
                sprintf(
                    'postgrestools could not report on %s:%d/%s and answered outside its JSON format%s',
                    $connection->host,
                    $connection->port,
                    $connection->database,
                    $this->stderrSuffix($result),
                ),
            );
        }

        if (! is_array($decoded) || ! is_array($decoded['diagnostics'] ?? null) || ! array_is_list($decoded['diagnostics'])) {
            return PglsRunResult::failed(
                PglsFailureReason::OutputUnreadable,
                'postgrestools reported valid JSON without the list of diagnostics this adapter reads',
            );
        }

        $findings = [];

        foreach ($decoded['diagnostics'] as $position => $entry) {
            $finding = PglsRawFinding::fromReportEntry($entry);

            if (! $finding instanceof PglsRawFinding) {
                return PglsRunResult::failed(
                    PglsFailureReason::OutputUnreadable,
                    sprintf('diagnostic %d is missing a required field, or carries a severity this adapter has not measured', $position),
                );
            }

            $findings[] = $finding;
        }

        return PglsRunResult::completed($findings);
    }

    private function outcomeDetail(ToolRunResult $result): string
    {
        return match ($result->outcome) {
            ToolRunOutcome::TimedOut => 'postgrestools did not finish inside its timeout, so nothing was measured'.$this->stderrSuffix($result),
            // The binary was found and the version accepted, so a start failure here means it
            // stopped being runnable between the two.
            default => sprintf('postgrestools could not be started (exit %d)%s', $result->exitCode, $this->stderrSuffix($result)),
        };
    }

    /** The tool's own complaint, when it made one — already bounded and redacted by the runner. */
    private function stderrSuffix(ToolRunResult $result): string
    {
        return $result->stderrExcerpt === '' ? '' : ': '.trim($result->stderrExcerpt);
    }
}
