<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp\Tools;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\JsonSchema\JsonSchema;
use Illuminate\Filesystem\Filesystem;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use Laravel\Mcp\Server\Attributes\Name;
use Override;
use Pushery\SQLens\Agent\Mcp\ReportPage;
use Pushery\SQLens\Agent\Mcp\ToolAnswer;
use Pushery\SQLens\Audit\ProjectManifest;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Reporting\Json\JsonEnvelope;
use Pushery\SQLens\Severity\Severity;

/**
 * `get_findings` — what the last run found, without running it again.
 *
 * ## Why it never runs anything
 *
 * An agent asking "what did the last run find" must not be able to start a database run by asking.
 * A second run would also answer about a different moment: the schema may have changed between the
 * question and the answer, and the agent would be reading a report of something it never saw.
 *
 * So this reads a file. No catalog, no connection, no capture.
 *
 * ## Why there is no path parameter
 *
 * The path comes from configuration. A free path argument on an MCP surface is a path-traversal
 * surface: an agent — or anything that can reach it — could read any file the process can. There
 * is no version of this tool where a caller names the file.
 *
 * ## Why "no report" and "no findings" cannot be confused
 *
 * They are the two sentences this tool exists to keep apart. An empty list reads as "the database
 * is clean"; a missing report means nobody has looked. The second answers `undetermined`, with the
 * reason and with the tool to call instead.
 */
#[Name('get_findings')]
final class GetFindingsTool extends SqlensTool
{
    protected string $description = 'Reads the findings of the last SQLens run from its report file: filter by severity, category or level, and page through them. Never runs anything and never opens a database.';

    public function mutating(): bool
    {
        return false;
    }

    /** See {@see GetDebtLedgerTool::handle()} for why the dependencies arrive as arguments. */
    public function handle(Request $request, Repository $config, ProjectManifest $manifest, Filesystem $files): Response
    {
        $validated = $this->validated($request);

        $configured = $config->get('sqlens.agent.mcp.findings_path');
        $path = is_string($configured) && $configured !== '' ? $configured : 'sqlens-report.json';
        $absolute = $manifest->root().'/'.$path;

        if (! $files->isFile($absolute)) {
            return ToolAnswer::undetermined(
                'no report exists at '.$path.' — that is not the same as a run with no findings. '
                .'Call lint_pending to produce one.',
                ['path' => $path],
            )->toResponse();
        }

        $decoded = json_decode((string) $files->get($absolute), true);

        if (! is_array($decoded)) {
            return ToolAnswer::undetermined(
                'the report at '.$path.' is present and could not be read as JSON',
                ['path' => $path],
            )->toResponse();
        }

        $version = $decoded['schema_version'] ?? null;

        if ($version !== JsonEnvelope::SCHEMA_VERSION) {
            // Refused rather than interpreted best-effort. A report from another schema names fields
            // that may mean something else now, and an answer built from it would be confidently
            // about the wrong thing.
            return ToolAnswer::undetermined(
                sprintf(
                    'the report at %s carries envelope schema %s and this build reads %d; re-run to produce one it can read',
                    $path,
                    is_scalar($version) ? (string) $version : 'nothing',
                    JsonEnvelope::SCHEMA_VERSION,
                ),
                ['path' => $path],
            )->toResponse();
        }

        $findings = $this->narrowed(
            array_values(array_filter(is_array($decoded['findings'] ?? null) ? $decoded['findings'] : [], is_array(...))),
            $validated,
        );

        $page = ReportPage::of(
            $findings,
            is_int($validated['offset'] ?? null) ? $validated['offset'] : 0,
            is_int($validated['limit'] ?? null) ? $validated['limit'] : null,
            $this->ceiling($config),
        );

        return ToolAnswer::of([
            // Suppressed findings are NOT here, and the count says how many there were. What the
            // baseline accepted stays accepted — an agent that saw them would go and fix things
            // somebody already decided to live with.
            'path' => $path,
            'suppressed' => is_int($decoded['suppressed'] ?? null) ? $decoded['suppressed'] : 0,
            ...$page->toArray(),
        ], sprintf('%d finding(s) in the last report, %d returned.', $page->total, count($page->rows)))->toResponse();
    }

    /** @return array<string, list<string>> */
    public function rules(): array
    {
        return [
            'severity_min' => ['sometimes', 'string', 'in:'.implode(',', array_column(Severity::cases(), 'value'))],
            'category' => ['sometimes', 'string', 'in:'.implode(',', array_column(Category::cases(), 'value'))],
            'level_max' => ['sometimes', 'integer', 'min:0', 'max:9'],
            'limit' => ['sometimes', 'integer', 'min:1', 'max:100000'],
            'offset' => ['sometimes', 'integer', 'min:0', 'max:100000'],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    #[Override]
    public function schema(JsonSchema $schema): array
    {
        return [
            'severity_min' => $schema->string()->description('Only findings at least this severe: '.implode(', ', array_column(Severity::cases(), 'value')).'.'),
            'category' => $schema->string()->description('Only findings in this category: '.implode(', ', array_column(Category::cases(), 'value')).'.'),
            'level_max' => $schema->integer()->description('Only findings at or below this strictness level (0-9).'),
            'limit' => $schema->integer()->description('At most this many findings. The project\'s own ceiling still applies, and a capped answer says so.'),
            'offset' => $schema->integer()->description('Skip this many findings, for paging through a long report.'),
        ];
    }

    /**
     * The findings a caller asked for.
     *
     * A finding whose severity or level this build cannot read is KEPT. The filter is a narrowing,
     * and dropping a row because a field was unreadable would answer a question about severity by
     * removing the row that raised it.
     *
     * @param  list<array<mixed>>  $findings
     * @param  array<string, mixed>  $validated
     * @return list<array<mixed>>
     */
    private function narrowed(array $findings, array $validated): array
    {
        $minimum = is_string($validated['severity_min'] ?? null) ? Severity::tryFrom($validated['severity_min']) : null;
        $category = $validated['category'] ?? null;
        $levelMax = $validated['level_max'] ?? null;

        return array_values(array_filter($findings, static function (array $finding) use ($minimum, $category, $levelMax): bool {
            if ($minimum instanceof Severity) {
                $severity = is_string($finding['severity'] ?? null) ? Severity::tryFrom($finding['severity']) : null;

                if ($severity instanceof Severity && ! $severity->isAtLeast($minimum)) {
                    return false;
                }
            }

            if (is_string($category) && is_string($finding['category'] ?? null) && $finding['category'] !== $category) {
                return false;
            }

            return ! is_int($levelMax) || ! is_int($finding['level'] ?? null) || $finding['level'] <= $levelMax;
        }));
    }

    /** The project's hard ceiling on one answer. */
    private function ceiling(Repository $config): int
    {
        $configured = $config->get('sqlens.agent.mcp.max_findings');

        return is_int($configured) && $configured >= 1 ? $configured : 200;
    }
}
