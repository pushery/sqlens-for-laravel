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
use Pushery\SQLens\Agent\Mcp\RunRefusal;
use Pushery\SQLens\Agent\Mcp\ToolAnswer;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Lint\LintRuns;
use Pushery\SQLens\Reporting\Json\JsonEnvelope;
use Pushery\SQLens\Subjects\CaptureMode;

/**
 * `lint_pending` — the core of the agent loop: what will this migration do.
 *
 * ## Why it calls the service and not the command
 *
 * The same {@see LintRuns} the CLI calls. Not `proc_open` on our own binary, and not a second
 * resolution path — the command is a second CONSUMER of this service, never the substrate of this
 * tool. Two paths into one engine would be two answers about one database, and the difference
 * would show up as an agent and a human disagreeing about a migration neither of them changed.
 *
 * ## Why the mode is not a parameter
 *
 * Pretend, always. Shadow creates and drops a database, so it is a separate tool behind its own
 * opt-in — and "separate tool" rather than "parameter" is the whole point: a parameter can be
 * passed by anything that can reach this one, and the enabling decision would move from the
 * project's configuration to the caller's argument.
 *
 * ## Why there is no exit code here
 *
 * A tool call never ends a process. Whether findings breached a gate is a FIELD an agent reads,
 * beside the findings themselves — the same information the CLI turns into an exit status, in the
 * form a caller over a protocol can act on.
 */
#[Name('lint_pending')]
final class LintPendingTool extends SqlensTool
{
    protected string $description = 'Lints the migrations a project has not run yet and returns structured findings — the same engine, rules and output as the sqlens:lint command. Runs in pretend mode: nothing is executed against the database.';

    public function mutating(): bool
    {
        return false;
    }

    /** See {@see GetDebtLedgerTool::handle()} for why the dependencies arrive as arguments. */
    public function handle(Request $request, Repository $config, LintRuns $runs): Response
    {
        $validated = $this->validated($request);

        $outcome = $runs->run(
            connection: is_string($validated['connection'] ?? null) ? $validated['connection'] : null,
            migrationPaths: null,
            // Pretend, hard-coded. Not a default a parameter can move: shadow creates and drops a
            // database, and reaching it from here would put that decision in a caller's argument.
            mode: CaptureMode::Pretend,
            level: is_int($validated['level'] ?? null) ? $validated['level'] : null,
            categories: is_string($validated['category'] ?? null) ? [$validated['category']] : null,
            // Handed straight to the engine's own single-file resolver, which is the one place that
            // decides whether a path names a migration this project lints. A pre-check here would be
            // a second answer to that question.
            files: is_string($validated['file'] ?? null) ? [$validated['file']] : [],
        );

        $envelope = JsonEnvelope::for($outcome->result, $outcome->context)->toArray();
        $findings = $envelope['findings'];

        $page = ReportPage::of($findings, 0, null, $this->ceiling($config));

        // The engine's OWN undetermined reasons, passed through rather than re-derived. Three-
        // valuedness is not reinvented in the agent layer: what the run could not determine is
        // counted in the envelope, and this lists the ones that actually occurred.
        $unresolved = $this->unresolvedReasons($envelope);

        // A run the engine never performed can only be undetermined, whatever the findings list
        // looks like — and an empty list is exactly what it looks like. Checked BEFORE the ordinary
        // answer, because the ordinary answer over a run that did not happen is the silent green.
        $answer = RunRefusal::in($outcome) ?? ($unresolved === []
            ? ToolAnswer::of([], $this->summary($outcome->connectionName, $page))
            : ToolAnswer::undetermined(
                'the run could not determine everything it looked at: '.implode(', ', $unresolved),
                [],
                // The paging sentence survives the undetermined one. A run can be both — some of it
                // unjudgeable AND its list cut — and a text client that only heard the first would
                // act on a short list believing it complete.
                $this->summary($outcome->connectionName, $page),
            ));

        return Response::json([
            ...$answer->toArray(),
            'connection' => $outcome->connectionName,
            // The gate decision as DATA. The CLI turns this into an exit status; a caller over a
            // protocol needs it in a form it can act on, beside the findings it is about.
            'gate' => [
                'breached' => $outcome->exitCode->value !== 0,
                'exit_code' => $outcome->exitCode->value,
                'meaning' => $outcome->exitCode->description(),
            ],
            // The envelope, whole and unchanged, so nothing about the report is re-derived here. A
            // second rendering of one run is a second thing that can disagree with it.
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
            // A NAME from the application's own connections, never a DSN. A free connection string
            // would let a caller point this tool at a database the project never configured — which
            // is the same class of hole as a free path, one layer down.
            'connection' => ['sometimes', 'string', 'in:'.implode(',', $this->connectionNames($config))],
            'profile' => ['sometimes', 'string', 'in:'.implode(',', $this->profileNames($config))],
            // Bounded AND patterned. The pattern refuses a traversal BEFORE anything touches the
            // filesystem, which is worth having on its own — but it is not the containment. That
            // belongs to the engine's own single-file resolver, which resolves the path and refuses
            // anything outside the configured migration paths, so `..`, an absolute foreign path and
            // a symlink that leaves are all already refused with a named reason. A second fence here
            // was measured to be both redundant and WRONG: it compared against the project root, so a
            // monorepo whose migration paths sit outside it got an answer from the command and a
            // refusal from the tool — two answers about one file, which is the divergence this whole
            // layer exists to prevent.
            'file' => ['sometimes', 'string', 'max:512', 'regex:/^[A-Za-z0-9._\\/-]+$/', 'not_regex:/\\.\\./'],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    #[Override]
    public function schema(JsonSchema $schema): array
    {
        return [
            'level' => $schema->integer()->description('Strictness level 0-9. Defaults to the project configuration.'),
            'category' => $schema->string()->description('Scope the run to one category: '.implode(', ', array_column(Category::cases(), 'value')).'.'),
            'connection' => $schema->string()->description('The name of a connection this application has configured. Never a connection string.'),
            'profile' => $schema->string()->description('The name of a run profile this project has configured.'),
            'file' => $schema->string()->description('A single project-relative migration file, for the sub-second path an editor loop uses.'),
        ];
    }

    /**
     * The undetermined reasons this run actually hit, from the envelope's own counts.
     *
     * Read rather than recomputed. The engine already decided what it could not determine and why;
     * a second reading in the agent layer would be a second answer, free to disagree with the
     * report a person sees for the same run.
     *
     * @param  array<string, mixed>  $envelope
     * @return list<string>
     */
    private function unresolvedReasons(array $envelope): array
    {
        $summary = $envelope['summary'] ?? null;
        $counts = is_array($summary) ? ($summary['counts'] ?? null) : null;
        $reasons = is_array($counts) ? ($counts['undetermined_reason'] ?? null) : null;
        $hit = [];

        foreach (is_array($reasons) ? $reasons : [] as $reason => $count) {
            if (is_int($count) && $count > 0) {
                $hit[] = (string) $reason;
            }
        }

        sort($hit);

        return $hit;
    }

    /**
     * A sentence for a client that shows text rather than structure.
     *
     * Deliberately a SUMMARY of the structured answer rather than a second reading of the run: an
     * agent acts on `findings` and the truncation field, and prose that said something different
     * from them would be the divergence this tool exists to avoid.
     */
    private function summary(string $connection, ReportPage $page): string
    {
        if ($page->total === 0) {
            return 'No findings on '.$connection.'.';
        }

        return sprintf(
            '%d finding(s) on %s, %d returned. %s',
            $page->total,
            $connection,
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

    /**
     * The run profiles this project has configured.
     *
     * @return list<string>
     */
    private function profileNames(Repository $config): array
    {
        $profiles = $config->get('sqlens.profiles');

        return array_values(array_filter(
            array_map(strval(...), array_keys(is_array($profiles) ? $profiles : [])),
            static fn (string $name): bool => $name !== '',
        ));
    }

    private function ceiling(Repository $config): int
    {
        $configured = $config->get('sqlens.agent.mcp.max_findings');

        return is_int($configured) && $configured >= 1 ? $configured : 200;
    }
}
