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
use Pushery\SQLens\Agent\Mcp\RunRefusal;
use Pushery\SQLens\Agent\Mcp\RunUnresolved;
use Pushery\SQLens\Agent\Mcp\ShadowRefusalAdvice;
use Pushery\SQLens\Agent\Mcp\ToolAnswer;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Config\ProfileApplication;
use Pushery\SQLens\Lint\LintRuns;
use Pushery\SQLens\Lint\ShadowClearance;
use Pushery\SQLens\Reporting\Json\JsonEnvelope;
use Pushery\SQLens\Subjects\CaptureMode;

/**
 * `lint_shadow` — the truth mode, reachable by an agent and never by accident.
 *
 * Shadow runs each pending migration for real against a throwaway database it creates and then
 * drops. That is the only way to know what a migration actually does, and it is also the one mode in
 * this package that writes anything at all. So it is a MUTATING tool: off unless a project enabled
 * it by name, and even then it cannot decide for itself whether a run may happen.
 *
 * ## The guard is asked, never rebuilt
 *
 * Everything about "may this run" lives in {@see ShadowClearance} and the production guard behind
 * it — the same verdict `sqlens:lint --shadow` gets, from the same gathering of the same inputs. This
 * tool passes the verdict to the engine and reads what came back. It cannot bypass the guard, and
 * more importantly it cannot ACCIDENTALLY diverge from it: there is nothing here to keep in step.
 *
 * ## Why there is no prompt, and no way to add one
 *
 * A protocol has nobody to ask. Laravel's confirmable path needs a terminal, and an MCP server has
 * none — so `interactive: false` is passed, and the guard's own rule then applies unchanged: without
 * an explicit yes, the run is refused rather than assumed. The explicit yes is a project setting
 * (`agent.mcp.shadow_consent`) that somebody wrote down in advance, deliberately NOT a parameter: a
 * consent a caller can send with the call is not consent, it is a field.
 *
 * That setting is also separate from enabling the tool, because they answer different questions —
 * one says an agent may ask, the other says a run may happen. And it is the weakest of the three
 * checks it can satisfy: the allowed-environment list and the production-connection detector refuse
 * regardless, and neither is overridable by anything.
 *
 * ## What a refusal looks like
 *
 * Never an empty result. A blocked run comes back as `undetermined`, with the guard's own named
 * check — `disallowed_environment`, `production_connection` or `not_confirmed` — read out of the run
 * header the engine produced rather than re-derived here, and a sentence saying what to do about
 * that particular one. The three need three different fixes, which is why the report distinguishes
 * them at all.
 */
#[Name('lint_shadow')]
final class LintShadowTool extends SqlensTool
{
    protected string $description = 'Runs the pending migrations for real against a throwaway shadow database and returns structured findings — the truth mode, which sees what static analysis cannot. It CREATES AND DROPS a database of its own and never touches project data. Disabled by default: a project must enable it by name and record its standing consent, because a server has nobody to ask.';

    public function mutating(): bool
    {
        return true;
    }

    /** See {@see GetDebtLedgerTool::handle()} for why the dependencies arrive as arguments. */
    public function handle(Request $request, Repository $config, LintRuns $runs, ShadowClearance $clearance): Response
    {
        $validated = $this->validated($request);
        $profiles = new ProfileApplication($config);

        // The profile `sqlens:lint --shadow` runs under when it is given no `--profile`:
        // SQLENS_PROFILE, then `sqlens.profile`. Not a parameter, as the mode is not one.
        $profile = $profiles->select(null);

        if (! $profile->isValid()) {
            return Response::json(ProfileRefusal::forLint((string) $profile->rejectedValue, $profile->source));
        }

        // Applied for this call and put back afterwards, because the next call is answered in the
        // same process.
        return $profiles->during($profile, fn (): Response => $this->answer($validated, $config, $runs, $clearance));
    }

    /**
     * The run and its answer, under the profile the call chose.
     *
     * @param  array<string, mixed>  $validated
     */
    private function answer(array $validated, Repository $config, LintRuns $runs, ShadowClearance $clearance): Response
    {
        $connection = new McpConnection($config)->chosen($validated['connection'] ?? null);

        $outcome = $runs->run(
            connection: $connection,
            migrationPaths: null,
            mode: CaptureMode::Shadow,
            level: is_int($validated['level'] ?? null) ? $validated['level'] : null,
            categories: is_string($validated['category'] ?? null) ? [$validated['category']] : null,
            guard: $clearance->decide(
                $connection,
                // The standing consent is the force. It is recorded as such in the run header, which
                // is honest: a run nobody was asked about, that happened anyway, IS a forced run.
                force: $config->get('sqlens.agent.mcp.shadow_consent') === true,
                // Nobody to ask, so nobody was asked. Both false, and the guard's own rule does the
                // rest — without the standing yes above, this combination is a refusal.
                interactive: false,
                confirmed: false,
            ),
        );

        $envelope = JsonEnvelope::for($outcome->result, $outcome->context)->toArray();
        $page = ReportPage::of($envelope['findings'], 0, null, $this->ceiling($config));
        $summary = trim($this->summary($outcome->connectionName, $page, RunUnresolved::reasons($envelope) === []).($outcome->staleBaselineBreaks ? ' '.$outcome->gateMeaning() : ''));

        // The run that never happened, then the guard's refusal, then the run that happened and
        // could not determine everything, and only then the ordinary answer. The third is not a
        // refusal: the guard allowed the run, and the captor found afterwards that no shadow could
        // be provisioned — behind a transaction pooler, on a replica — and judged every migration
        // undetermined without creating a database.
        $answer = RunRefusal::in($outcome)
            ?? $this->refusal($this->guardBlock($envelope))
            ?? RunUnresolved::in($envelope, $summary)
            ?? ToolAnswer::of([], $summary);

        return Response::json([
            ...$answer->toArray(),
            'connection' => $outcome->connectionName,
            'gate' => [
                'breached' => $outcome->exitCode->value !== 0,
                'exit_code' => $outcome->exitCode->value,
                'meaning' => $outcome->gateMeaning(),
            ],
            // The contract the findings below are shaped by. The CLI's JSON consumer is told this
            // and an MCP caller was not, which made the version a promise kept in one channel only —
            // an agent reading these fields had no way to know which contract it was holding.
            'schema_version' => $envelope['schema_version'],
            'run' => $envelope['run'],
            'counts' => $envelope['summary'],
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
            'level' => ['sometimes', 'integer', 'min:0', 'max:9'],
            'category' => ['sometimes', 'string', 'in:'.implode(',', array_column(Category::cases(), 'value'))],
            'connection' => ['sometimes', 'string', 'in:'.implode(',', new McpConnection($config)->allowed())],
        ];
    }

    /**
     * The parameters this tool does NOT take, and it is a short list on purpose.
     *
     * No `file`: the fast path is pretend-only by construction, and `lint_pending` is where it lives.
     * No confirmation, no force, no environment override — every one of those would move a decision
     * the project made into the caller's argument, which is the whole thing the opt-in exists to
     * prevent.
     *
     * @return array<string, mixed>
     */
    #[Override]
    public function schema(JsonSchema $schema): array
    {
        return [
            'level' => $schema->integer()->description('Strictness level 0-9. Defaults to the project configuration.'),
            'category' => $schema->string()->description('Scope the run to one category: '.implode(', ', array_column(Category::cases(), 'value')).'.'),
            'connection' => $schema->string()->description('The name of a connection this application has configured, and only the one sqlens.agent.mcp.connection names when it is set. Never a connection string.'),
        ];
    }

    /**
     * The guard's named check, from the run header the engine wrote — or null when it allowed the run.
     *
     * Read rather than recomputed, and that is the point of the field existing. Asking the clearance
     * a second time would be a second decision about one run, and the two would agree right up until
     * something changed between them.
     *
     * @param  array<string, mixed>  $envelope
     */
    private function guardBlock(array $envelope): ?string
    {
        $run = is_array($envelope['run'] ?? null) ? $envelope['run'] : [];
        $guard = is_array($run['guard'] ?? null) ? $run['guard'] : [];
        $verdict = $guard['guard'] ?? null;

        return is_string($verdict) && $verdict !== 'allowed' ? $verdict : null;
    }

    /** The refusal, with the sentence that fits the check that actually refused, or null when none did. */
    private function refusal(?string $check): ?ToolAnswer
    {
        if ($check === null) {
            return null;
        }

        return ToolAnswer::undetermined(
            ShadowRefusalAdvice::for($check),
            // Structured beside the sentence, and it is the guard's own identifier — the same string
            // the run header carries and the same one the CLI reports.
            ['refusal' => ['id' => $check]],
        );
    }

    /**
     * A sentence for a client that shows text rather than structure.
     *
     * It names the mode in words, so a shadow answer cannot be mistaken for a pretend one. It says
     * the findings came from a real run against a throwaway database only when the run determined
     * everything it looked at, because only then did one certainly exist: a shadow that could not be
     * provisioned leaves every migration undetermined, and no database was ever created.
     */
    private function summary(string $connection, ReportPage $page, bool $determined): string
    {
        $source = $determined ? 'from a real run against a throwaway database' : 'in shadow mode';

        if ($page->total === 0) {
            return 'No findings on '.$connection.', '.$source.'.';
        }

        return sprintf(
            '%d finding(s) on %s %s, %d returned. %s',
            $page->total,
            $connection,
            $source,
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
