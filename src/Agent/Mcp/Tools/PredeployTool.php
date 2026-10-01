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
use Pushery\SQLens\Agent\Mcp\McpConnection;
use Pushery\SQLens\Agent\Mcp\ProfileRefusal;
use Pushery\SQLens\Agent\Mcp\ReportPage;
use Pushery\SQLens\Agent\Mcp\ToolAnswer;
use Pushery\SQLens\Config\ProfileApplication;
use Pushery\SQLens\Deploy\PreflightBlocker;
use Pushery\SQLens\Deploy\PreflightOutcome;
use Pushery\SQLens\Deploy\PreflightReport;
use Pushery\SQLens\Deploy\PreflightRuns;
use Pushery\SQLens\Deploy\PreflightVerdict;
use Pushery\SQLens\Deploy\UndeterminedWaiver;
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
 * ## Leaving the parameter out falls back to the project's declaration, and that is the whole point
 *
 * The parameter is the counterpart of the command's `--allow-undetermined` flag: a person watching
 * this run decide to proceed, all-or-nothing on both sides. It is not the counterpart of the config
 * key, which is a project deciding in advance which questions it can deploy without and naming
 * them. So an explicit parameter wins in both directions, and its absence reads
 * `sqlens.deploy.predeploy.allow_undetermined` — the same source, through the same
 * {@see UndeterminedWaiver}, as the `sqlens:predeploy` console command.
 *
 * That command is named in prose and not as a `{@see}`, which is not a style choice. A
 * fully-qualified reference in a docblock is rewritten into a real `use` statement by the
 * formatter, and an import out of `Console\` is a coupling this layer is built not to have.
 *
 * Absence does not mean `false`: a project that has named the reasons it can deploy past gets them
 * honored here exactly as on the command line, for the same run — {@see gate()} below promises in as
 * many words that the two paths cannot disagree.
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

        // Two ways in, one door — the same join the command makes, for the same reason. The
        // parameter decides it either way when it is present; leaving it out is what falls back to
        // what the project declared.
        $waiver = array_key_exists('allow_undetermined', $validated)
            ? ($validated['allow_undetermined'] === true ? UndeterminedWaiver::everyReason() : UndeterminedWaiver::closed())
            : UndeterminedWaiver::fromConfig($config->get('sqlens.deploy.predeploy.allow_undetermined'));

        // The fact a deploy log needs even when nothing went unanswered: was the hatch open at all.
        // Whether it was USED is a different question and travels in the run header below.
        $allowUndetermined = $waiver->opensAnything();

        $profiles = new ProfileApplication($config);

        // The profile `sqlens:predeploy` runs under: SQLENS_PROFILE, then `sqlens.profile`, then
        // its own default `predeploy`, the paranoid one. Not a parameter, and neither is the budget:
        // a caller that could move either would be deciding how careful this gate is on a per-call
        // basis, which is the decision the configuration exists to hold.
        $profile = $profiles->select(null, 'predeploy');

        if (! $profile->isValid()) {
            return Response::json([
                ...ProfileRefusal::answer((string) $profile->rejectedValue, $profile->source)->toArray(),
                // Blocks, as a gate that could not run blocks: nothing about this deploy was
                // established.
                'gate' => $this->gate(PreflightVerdict::of(PreflightBlocker::Refused)),
                'allow_undetermined' => $allowUndetermined,
            ]);
        }

        // Applied for this call and put back afterwards, because the next call is answered in the
        // same process.
        return $profiles->during($profile, fn (): Response => $this->answer($validated, $config, $preflight, $waiver, $profile->profile));
    }

    /**
     * The gate and its answer, under the profile the call chose.
     *
     * @param  array<string, mixed>  $validated
     */
    private function answer(array $validated, Repository $config, PreflightRuns $preflight, UndeterminedWaiver $waiver, ?string $profile): Response
    {
        $allowUndetermined = $waiver->opensAnything();

        $outcome = $preflight->run(
            connection: new McpConnection($config)->chosen($validated['connection'] ?? null),
            // Handed over as the command hands over its own, so the run's context names the profile
            // whose settings it ran on.
            profile: $profile,
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
                // `false`, not the waiver: a gate that could not RUN has no unanswered checks to
                // waive, and a waiver cannot carry a deploy past a missing gate.
                'gate' => $this->gate($outcome->verdict($waiver)),
                'allow_undetermined' => $allowUndetermined,
            ]);
        }

        // Word for word the command's join: blocked, blocked by nothing BUT unanswered checks, and
        // every one of them covered. Partial coverage is the one result that must not read as
        // permission.
        $verdict = $outcome->verdict($waiver);

        // Carried on the context rather than assembled here, so `run.undetermined_waiver` says the
        // same thing over the protocol as it does on the command line. Left off, it stayed null —
        // "this producer has no gate at all", which on this path is simply untrue.
        $envelope = JsonEnvelope::for(
            $outcome->result,
            $outcome->context->withUndeterminedWaiver($verdict->waived(), $verdict->waivedReasons),
        )->toArray();
        $page = ReportPage::of($envelope['findings'], 0, null, $this->ceiling($config));

        // Both halves. An undetermined finding about a pending migration is a question this run left
        // open as much as an unanswered check is, and `status` is where an agent reads that — even
        // where the profile lets the deploy proceed past it, which `gate` says.
        $unresolved = $outcome->unanswered();

        $answer = $unresolved === []
            ? ToolAnswer::of([], $this->summary($outcome, $page))
            : ToolAnswer::undetermined(
                'what could not be answered: '.implode(', ', $unresolved),
                [],
                $this->summary($outcome, $page),
            );

        return Response::json([
            ...$answer->toArray(),
            'connection' => $outcome->connection,
            'gate' => $this->gate($verdict),
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
            'connection' => ['sometimes', 'string', 'in:'.implode(',', new McpConnection($config)->allowed())],
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
            'connection' => $schema->string()->description('The name of a connection this application has configured, and only the one sqlens.agent.mcp.connection names when it is set. Never a connection string.'),
            'allow_undetermined' => $schema->boolean()->description('Proceed when the ONLY blockers are checks that could not answer. Leave it out to use what the project declared in sqlens.deploy.predeploy.allow_undetermined, which may name individual reasons; passing it decides this run either way, all-or-nothing. A real failure still blocks, and whichever applied is recorded in the answer.'),
        ];
    }

    /**
     * The gate decision as data — the same four-code contract the command turns into an exit status.
     *
     * Read off the outcome's verdict rather than decided here: the command and this tool must not be
     * able to disagree about whether a deploy proceeds, and two readings of the same run are two
     * chances to.
     *
     * @return array{blocks: bool, exit_code: int, meaning: string}
     */
    private function gate(PreflightVerdict $verdict): array
    {
        return [
            'blocks' => $verdict->blocks(),
            'exit_code' => $verdict->exitCode()->value,
            'meaning' => match ($verdict->blocker) {
                PreflightBlocker::Nothing => 'Nothing blocked: no check failed and no finding about the pending migrations crossed the gate. The deploy may proceed.',
                PreflightBlocker::Waived => 'The only blockers were answers that could not be given, and a waiver covering every one of them let the deploy proceed. Which reasons it named is in the run header.',
                PreflightBlocker::Unanswered => 'Every blocker is an answer that could not be given, and no waiver covers all of them. Fail-closed: it blocks.',
                PreflightBlocker::CheckFailed => 'A check found a real problem with this deploy.',
                PreflightBlocker::MigrationFinding => 'A finding about a pending migration crossed the gate, so the deploy would run what it reports.',
                PreflightBlocker::Refused => 'The gate could not run, so nothing about this deploy was established. Fail-closed: it blocks.',
                PreflightBlocker::StaleBaseline => 'Baseline entries matched nothing and sqlens.baseline.stale is error, so the baseline counts as misconfigured and the deploy is held back. The checks and the pending migrations were judged; the stale entries are in the report.',
            },
        ];
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

    private function ceiling(Repository $config): int
    {
        $configured = $config->get('sqlens.agent.mcp.max_findings');

        return is_int($configured) && $configured >= 1 ? $configured : 200;
    }
}
