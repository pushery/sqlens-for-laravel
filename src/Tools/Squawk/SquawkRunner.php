<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Squawk;

use JsonException;
use Pushery\SQLens\Tools\ProcessRunner;
use Pushery\SQLens\Tools\ToolPayload;
use Pushery\SQLens\Tools\ToolRunOutcome;
use Pushery\SQLens\Tools\ToolRunResult;

/**
 * Runs Squawk over a captured migration and reads its report.
 *
 * It touches no database and writes no file. The SQL travels on standard input and the findings
 * come back on standard output, so the whole interaction lives and dies with one subprocess —
 * there is no temp file to clean up, which means there is no error path that fails to clean one
 * up. That was measured rather than assumed: the tool reads stdin when given no path, and
 * `--stdin-filepath` decides the path it reports findings under.
 *
 * Nothing here throws. An amplifier that is asked a question must never be able to end the run
 * that asked it, so every way this can go wrong ends as a named reason.
 */
final readonly class SquawkRunner
{
    /**
     * A config file the tool reads is a config file that changes the answer.
     *
     * A `.squawk.toml` in the working directory IS read and DOES change results — measured: one
     * excluded rule, one finding fewer, nothing anywhere saying so. Since SQLens maps this tool's
     * rules onto its own ids, levels and downtime classes, such a file would silence a SQLENS
     * rule without ever passing through the baseline or the ignore list, which are the two places
     * a suppression is supposed to be visible. So the tool is pointed at the null device and the
     * project's own file has no effect; suppression belongs in `sqlens.ignore`, where it shows up
     * in the report.
     *
     * The null device is safe to name absolutely: this tool has no Windows build at all.
     */
    private const string NEUTRAL_CONFIG = '/dev/null';

    /** The exit codes the tool's contract uses: nothing found, and something found. */
    private const array CONTRACT_EXIT_CODES = [0, 1];

    public function __construct(private ProcessRunner $runner) {}

    /**
     * Lint one prepared document and read what comes back.
     *
     * @param  string  $binaryPath  the binary the locator resolved and the version gate accepted
     */
    public function run(string $binaryPath, ToolPayload $payload, SquawkInvocation $invocation): SquawkRunResult
    {
        $result = $this->runner->run(
            $binaryPath,
            $this->arguments($invocation),
            $invocation->timeoutSeconds,
            $payload->sql,
        );

        if ($result->outcome !== ToolRunOutcome::Completed) {
            return SquawkRunResult::failed(
                SquawkFailureReason::RunFailed,
                $this->outcomeDetail($result),
            );
        }

        // A code outside the contract means the tool is telling us something this adapter was
        // not written to hear. Reading its output anyway would be reading a report whose status
        // we do not understand — and an unrecognized status is exactly when output is least
        // trustworthy.
        if (! in_array($result->exitCode, self::CONTRACT_EXIT_CODES, true)) {
            return SquawkRunResult::failed(
                SquawkFailureReason::RunFailed,
                sprintf('squawk exited %d, which is not part of its exit-code contract%s', $result->exitCode, $this->stderrSuffix($result)),
            );
        }

        return $this->read($result);
    }

    /**
     * The argv, in a fixed order.
     *
     * Fixed because determinism reaches this far down: two runs of the same migration must send
     * the same bytes to the same program, so a report can be compared with the one before it.
     * No path argument at all — that is what makes the tool read standard input.
     *
     * @return list<string>
     */
    private function arguments(SquawkInvocation $invocation): array
    {
        $arguments = [
            '--reporter', 'json',
            '--config', self::NEUTRAL_CONFIG,
            '--stdin-filepath', $invocation->reportedPath,
        ];

        if ($invocation->pgVersion !== null) {
            $arguments[] = '--pg-version';
            $arguments[] = $invocation->pgVersion;
        }

        // Only when SQLens actually knows. The tool has its own default, and overriding it with
        // a guess would be inventing a fact about how the migration runs.
        if ($invocation->insideTransaction !== null) {
            $arguments[] = $invocation->insideTransaction ? '--assume-in-transaction' : '--no-assume-in-transaction';
        }

        return $arguments;
    }

    /** Read the report, or say which way it was not one. */
    private function read(ToolRunResult $result): SquawkRunResult
    {
        try {
            $decoded = json_decode($result->stdout, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            // Measured: this is also how a tool-level error arrives. Asked for a file that does
            // not exist, the tool exits 1 with an EMPTY stdout and its complaint on stderr — so
            // the absence of a report, not the exit code, is what says the run failed.
            return SquawkRunResult::failed(
                SquawkFailureReason::RunFailed,
                sprintf('squawk exited %d without a JSON report (%s)%s', $result->exitCode, $e->getMessage(), $this->stderrSuffix($result)),
            );
        }

        if (! is_array($decoded) || ! array_is_list($decoded)) {
            return SquawkRunResult::failed(
                SquawkFailureReason::OutputUnreadable,
                'squawk reported valid JSON that is not the flat array of findings this adapter reads',
            );
        }

        $findings = [];

        foreach ($decoded as $position => $entry) {
            $finding = SquawkRawFinding::fromReportEntry($entry);

            if (! $finding instanceof SquawkRawFinding) {
                return SquawkRunResult::failed(
                    SquawkFailureReason::OutputUnreadable,
                    sprintf('entry %d of the squawk report is missing a required field or has one of an unexpected type', $position),
                );
            }

            $findings[] = $finding;
        }

        return $this->syntaxErrorIn($findings) ?? SquawkRunResult::completed($findings);
    }

    /**
     * A parse failure ends the whole report, not just its own entry.
     *
     * The tool stops understanding the document at the point it breaks, so every rule after it
     * had nothing to judge. Handing back the entries that did arrive would present an analysis
     * that stopped early as one that finished — which is the same shape as a clean result and
     * the exact failure "no silent green" exists to prevent.
     *
     * @param  list<SquawkRawFinding>  $findings
     */
    private function syntaxErrorIn(array $findings): ?SquawkRunResult
    {
        foreach ($findings as $finding) {
            if ($finding->isSyntaxError()) {
                return SquawkRunResult::failed(
                    SquawkFailureReason::Unparsable,
                    sprintf('squawk could not parse the captured SQL: %s', $finding->message),
                );
            }
        }

        return null;
    }

    private function outcomeDetail(ToolRunResult $result): string
    {
        return match ($result->outcome) {
            ToolRunOutcome::TimedOut => 'squawk did not finish inside its timeout, so nothing was measured'.$this->stderrSuffix($result),
            // The binary was found and the version accepted, so a start failure here means it
            // stopped being runnable between the two — worth saying plainly rather than folding
            // into a generic failure.
            default => sprintf('squawk could not be started (exit %d)%s', $result->exitCode, $this->stderrSuffix($result)),
        };
    }

    /** The tool's own complaint, when it made one — already bounded and redacted by the runner. */
    private function stderrSuffix(ToolRunResult $result): string
    {
        return $result->stderrExcerpt === '' ? '' : ': '.trim($result->stderrExcerpt);
    }
}
