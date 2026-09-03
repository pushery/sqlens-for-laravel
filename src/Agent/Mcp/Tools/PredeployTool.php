<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp\Tools;

use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\JsonSchema\JsonSchema;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use Laravel\Mcp\Server\Attributes\Name;
use Override;
use Pushery\SQLens\Agent\Mcp\ReportPage;
use Pushery\SQLens\Agent\Mcp\ToolAnswer;
use Pushery\SQLens\Deploy\PreflightOutcome;
use Pushery\SQLens\Deploy\PreflightReport;
use Pushery\SQLens\Deploy\PreflightRuns;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Reporting\Json\JsonEnvelope;
use Pushery\SQLens\Reporting\RunContext;

/**
 * `predeploy` — the gate that runs immediately before `migrate --force`, over the protocol.
 *
 * ## Why it is mutating
 *
 * It reads and only reads: catalog and state views, a session it bounds itself, never a lock of its
 * own. Nothing about the database changes. It is declared mutating anyway, because it reaches a
 * REAL, named target database — the production one, at the moment before a deploy — and the opt-in
 * this package spends its care on is about reach rather than about writes. A tool an agent can point
 * at production is a tool a project decides to enable.
 *
 * ## Fail-closed survives the protocol
 *
 * A run that could not look has not established that the deploy is safe. Over the protocol that
 * means `status: undetermined` with the named reason and a gate block that says it blocks — never an
 * empty finding list, which is what "no problems" looks like to anything reading quickly. A target
 * that cannot be resolved or reached is exactly that case, and it is the one the DoD names.
 *
 * ## `allow_undetermined` is a parameter, and it is VISIBLE
 *
 * Unlike the shadow tool's consent, this one belongs to the caller: it does not grant reach, it
 * decides what to do about a gate that could not answer, which is a per-run judgment a deploy
 * pipeline legitimately makes. What it must never be is invisible — so it is echoed in the answer
 * whether or not it changed anything, and a run that used it says so beside the verdict it produced.
 *
 * ## The budget and the session defense are the service's
 *
 * The time budget, the session's own `statement_timeout` / `lock_timeout` and the rule that the gate
 * never takes a lock of its own all live in {@see PreflightRuns}. This tool cannot reach them,
 * cannot relax them, and — the part that matters — cannot accidentally diverge from them.
 */
#[Name('predeploy')]
final class PredeployTool extends SqlensTool
{
    protected string $description = 'Runs the predeploy gate against the target database immediately before a deploy: read-only, time-bounded, fail-closed. Returns the pending migrations and the instance checks as one verdict, each finding carrying its downtime class. Disabled by default, because it reaches a real named database.';

    public function mutating(): bool
    {
        return true;
    }

    /** See {@see GetDebtLedgerTool::handle()} for why the dependencies arrive as arguments. */
    public function handle(Request $request, Repository $config, PreflightRuns $preflight): Response
    {
        $validated = $this->validated($request);
        $allowUndetermined = ($validated['allow_undetermined'] ?? false) === true;

        $outcome = $preflight->run(
            connection: is_string($validated['connection'] ?? null) ? $validated['connection'] : null,
            // Not parameters. The profile is `predeploy` — the paranoid one — and the budget is the
            // project's; a caller that could raise either would be deciding how careful this gate is
            // on a per-call basis, which is the decision the configuration exists to hold.
        );

        if (! $outcome->result instanceof Result || ! $outcome->context instanceof RunContext || ! $outcome->report instanceof PreflightReport) {
            // Nothing was learned about the database. Fail-closed means this can never read as a
            // pass, so it is undetermined with the service's own reason — and the gate block says
            // it blocks, because a deploy must not proceed on a gate that could not run.
            return Response::json([
                ...ToolAnswer::undetermined((string) $outcome->refusal, [
                    'refusal' => ['id' => 'preflight_unavailable', 'connection' => $outcome->connection],
                ])->toArray(),
                'connection' => $outcome->connection,
                'gate' => $this->gate($outcome, $allowUndetermined),
                'allow_undetermined' => $allowUndetermined,
            ]);
        }

        $envelope = JsonEnvelope::for($outcome->result, $outcome->context)->toArray();
        $page = ReportPage::of($envelope['findings'], 0, null, $this->ceiling($config));
        $unresolved = $outcome->report->undetermined();

        $answer = $unresolved === []
            ? ToolAnswer::of([], $this->summary($outcome, $page))
            : ToolAnswer::undetermined(
                'checks that could not answer: '.implode(', ', array_map(
                    static fn (object $result): string => $result->checkId.' ('.$result->reason.')',
                    $unresolved,
                )),
                [],
                $this->summary($outcome, $page),
            );

        return Response::json([
            ...$answer->toArray(),
            'connection' => $outcome->connection,
            'gate' => $this->gate($outcome, $allowUndetermined),
            // Echoed whether or not it changed anything. An emergency exit that could be used
            // invisibly is not an emergency exit, it is a default nobody agreed to — and the one
            // reading a deploy log afterwards is the person who needs to see it most.
            'allow_undetermined' => $allowUndetermined,
            // The contract the findings below are shaped by. The CLI's JSON consumer is told this
            // and an MCP caller was not, which made the version a promise kept in one channel only —
            // an agent reading these fields had no way to know which contract it was holding.
            'schema_version' => $envelope['schema_version'],
            'run' => $envelope['run'],
            'counts' => $envelope['summary'],
            // The findings whole, so `downtime_class` and the severity axis survive the protocol —
            // which is the value of this tool to an agent rewriting a migration.
            ...$page->toArray(),
        ]);
    }

    /**
     * @return array<string, list<string>>
     */
    public function rules(): array
    {
        $config = Container::getInstance()->make('config');

        return [
            // A NAME from the application's own connections, never a DSN. On the one tool that
            // reaches a production database, a free connection string would be the whole game.
            'connection' => ['sometimes', 'string', 'in:'.implode(',', $this->connectionNames($config))],
            'allow_undetermined' => ['sometimes', 'boolean'],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    #[Override]
    public function schema(JsonSchema $schema): array
    {
        return [
            'connection' => $schema->string()->description('The name of a connection this application has configured. Never a connection string.'),
            'allow_undetermined' => $schema->boolean()->description('Proceed when the ONLY blockers are checks that could not answer. Fail-closed is the default; a real failure still blocks, and using this is recorded in the answer.'),
        ];
    }

    /**
     * The gate decision as data — the same four-code contract the command turns into an exit status.
     *
     * Derived from the outcome's own answer about what blocked rather than re-counted here: the
     * command and this tool must not be able to disagree about whether a deploy proceeds, and two
     * readings of the same results are two chances to.
     *
     * @return array{blocks: bool, exit_code: int, meaning: string}
     */
    private function gate(PreflightOutcome $outcome, bool $allowUndetermined): array
    {
        if (! $outcome->report instanceof PreflightReport) {
            return [
                'blocks' => true,
                'exit_code' => 2,
                'meaning' => 'The gate could not run, so nothing about this deploy was established. Fail-closed: it blocks.',
            ];
        }

        if (! $outcome->report->blocks()) {
            return ['blocks' => false, 'exit_code' => 0, 'meaning' => 'No check blocked; the deploy may proceed.'];
        }

        $onlyUndetermined = $outcome->blockedOnlyByUndetermined();

        if ($onlyUndetermined && $allowUndetermined) {
            return [
                'blocks' => false,
                'exit_code' => 0,
                'meaning' => 'The only blockers were checks that could not answer, and allow_undetermined let the deploy proceed.',
            ];
        }

        return $onlyUndetermined
            ? ['blocks' => true, 'exit_code' => 3, 'meaning' => 'Every blocker is a check that could not answer. Fail-closed: it blocks.']
            : ['blocks' => true, 'exit_code' => 1, 'meaning' => 'A check found a real problem with this deploy.'];
    }

    /** A sentence for a client that shows text rather than structure. */
    private function summary(PreflightOutcome $outcome, ReportPage $page): string
    {
        if ($page->total === 0) {
            return 'Nothing blocked the deploy on '.$outcome->connection.'.';
        }

        return sprintf(
            '%d finding(s) before the deploy on %s, %d returned. %s',
            $page->total,
            (string) $outcome->connection,
            count($page->rows),
            $page->truncated ? 'The list is CUT: '.$page->reason.'.' : 'Nothing was left out.',
        );
    }

    /**
     * The connection names this application has configured.
     *
     * @return list<string>
     */
    private function connectionNames(Repository $config): array
    {
        $connections = $config->get('database.connections');

        return array_values(array_filter(
            array_map(strval(...), array_keys(is_array($connections) ? $connections : [])),
            static fn (string $name): bool => $name !== '',
        ));
    }

    private function ceiling(Repository $config): int
    {
        $configured = $config->get('sqlens.agent.mcp.max_findings');

        return is_int($configured) && $configured >= 1 ? $configured : 200;
    }
}
