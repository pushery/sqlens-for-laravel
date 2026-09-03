<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Squawk;

use Pushery\SQLens\Capture\CaptureResult;
use Pushery\SQLens\Capture\CaptureRun;
use Pushery\SQLens\Engine\ResolvedServerVersion;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Outcome;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Subjects\SubjectContext;
use Pushery\SQLens\Tools\ToolDiagnostic;
use Pushery\SQLens\Tools\ToolPayload;
use Pushery\SQLens\Tools\ToolPositionMapper;

/**
 * What Squawk adds to one lint run — the single place the whole adapter chain is assembled.
 *
 * One seam rather than six calls scattered through the runner, because the order is load-bearing
 * and the guarantees only hold end to end: the run's own findings must come out unchanged, the
 * tool's must be placed before they are mapped, and de-duplication has to happen BEFORE
 * suppression or a baseline gets pinned to findings that were about to be merged.
 *
 * It is invoked per MIGRATION, not per run. One invocation carries one reported path and one
 * transaction assumption, and a run that handed the tool everything at once would have to pick
 * one of each for migrations that disagree.
 *
 * Nothing here can end the run. Every failure of the tool becomes a named undetermined finding,
 * because an amplifier that was asked a question must never be able to stop the run that asked.
 */
final readonly class SquawkContribution
{
    /**
     * The bound one invocation gets when the project sets none.
     *
     * It mirrors the shipped config value rather than duplicating a policy: the two are checked
     * against each other, so a default that drifted out of the config file cannot go unnoticed.
     */
    public const float DEFAULT_TIMEOUT_SECONDS = 10.0;

    public function __construct(
        private SquawkRunner $runner,
        private SquawkFindingMapper $mapper,
        private SquawkDeduplicator $deduplicator,
        private ToolPositionMapper $positions,
        private float $timeoutSeconds,
        /**
         * Whether the tool may run in the single-file fast path.
         *
         * Off in the shipped config. The fast path promises sub-second turnaround so a pre-commit
         * hook or an editor-save loop stays usable, and a subprocess is exactly the cost that
         * promise cannot absorb by accident. Turning it on is a trade somebody makes on purpose.
         */
        private bool $onFastPath,
    ) {}

    /**
     * The run's findings, some of them confirmed, plus whatever only the tool found.
     *
     * @param  list<Finding>  $own
     * @return list<Finding>
     */
    public function contribute(
        array $own,
        CaptureRun $run,
        ToolDiagnostic $diagnostic,
        ResolvedServerVersion $version,
        SubjectContext $context,
        Level $gate,
        bool $fastPath = false,
    ): array {
        // Nothing to run against, and nothing to say about it: the run already reports an
        // unavailable tool as its own named finding, from the diagnostic. Repeating it here would
        // be the same absence twice.
        if (! $diagnostic->isAvailable() || $diagnostic->path === null) {
            return $own;
        }

        if ($fastPath && ! $this->onFastPath) {
            // Named, not silent. The project wants these checks — it capped where they may cost a
            // second — so a run that simply left them out would be a smaller check with the same
            // face as a full one.
            return [...$own, ...array_map(
                fn (CaptureResult $result): Finding => $this->degraded(SquawkFailureReason::SkippedOnFastPath, $result, $context),
                $run->results,
            )];
        }

        $tool = [];

        foreach ($run->results as $result) {
            foreach ($this->forMigration($result, $diagnostic, $version, $context) as $finding) {
                $tool[] = $finding;
            }
        }

        $merged = $this->deduplicator->merge($own, $this->withinGate($tool, $gate));

        return $merged->all();
    }

    /**
     * The tool's findings the run's LEVEL admits — the same gate a rule finding passes.
     *
     * Without it an installed binary sharpens a gate the user narrowed on purpose, which is the
     * one thing an amplifier must never do: the level band is an appetite the project chose, and
     * a tool has no standing to overrule it.
     *
     * The gate applies to VERDICTS only. A degradation is undetermined — it says the tool could
     * not answer — and that is governed by the undetermined policy and strict mode, not by an
     * appetite for strictness. Silencing it at a low level would turn "nobody checked" into
     * "nothing found", which is the silent green this package exists to refuse.
     *
     * @param  list<Finding>  $findings
     * @return list<Finding>
     */
    private function withinGate(array $findings, Level $gate): array
    {
        return array_values(array_filter(
            $findings,
            static fn (Finding $finding): bool => $finding->status->outcome === Outcome::Undetermined
                || $finding->level->value <= $gate->value,
        ));
    }

    /**
     * @return list<Finding> what the tool contributed for ONE migration
     */
    private function forMigration(
        CaptureResult $result,
        ToolDiagnostic $diagnostic,
        ResolvedServerVersion $version,
        SubjectContext $context,
    ): array {
        $statements = SquawkStatements::of($result);

        if ($statements === []) {
            return [];
        }

        $payload = ToolPayload::of($statements);
        $assumedVersion = SquawkServerVersionAssumption::forRun($version);
        $transaction = SquawkTransactionAssumption::forMigration($statements);

        // An assumption SQLens could not establish is reported, not replaced by the tool's own
        // default. Running anyway would produce a verdict about a different server, or a different
        // transaction model, inside a report that says nothing about the substitution.
        foreach ([$assumedVersion, $transaction] as $assumption) {
            if ($assumption instanceof SquawkFailureReason) {
                return [$this->degraded($assumption, $result, $context)];
            }
        }

        $outcome = $this->runner->run(
            $diagnostic->path ?? '',
            $payload,
            new SquawkInvocation(
                reportedPath: $result->file,
                pgVersion: is_string($assumedVersion) ? $assumedVersion : null,
                insideTransaction: is_bool($transaction) ? $transaction : null,
                timeoutSeconds: $this->timeoutSeconds,
            ),
        );

        if (! $outcome->produced()) {
            return [$this->degraded($outcome->failure ?? SquawkFailureReason::RunFailed, $result, $context, $outcome->detail)];
        }

        $findings = [];

        foreach ($outcome->findings as $raw) {
            $finding = $this->mapper->map($raw, $this->positions->atZeroBasedLine($payload, $raw->zeroBasedLine), $context);

            if ($finding instanceof Finding) {
                $findings[] = $finding;
            }
        }

        return $findings;
    }

    /**
     * A degradation of the TOOL's contribution — never of the run.
     *
     * It names the migration it is about, because a run over forty migrations that said only
     * "squawk failed" would leave a reader with nowhere to look.
     */
    private function degraded(SquawkFailureReason $reason, CaptureResult $result, SubjectContext $context, string $detail = ''): Finding
    {
        return $this->mapper->degradation($reason, $result, $context, $detail);
    }
}
