<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp\Tools;

use DateTimeImmutable;
use DateTimeZone;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\JsonSchema\JsonSchema;
use Illuminate\Filesystem\Filesystem;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use Laravel\Mcp\Server\Attributes\Name;
use Override;
use Pushery\SQLens\Agent\Mcp\ToolAnswer;
use Pushery\SQLens\Audit\ProjectManifest;
use Pushery\SQLens\Config\ConfigSchema;
use Pushery\SQLens\Deploy\DebtAge;
use Pushery\SQLens\Deploy\DebtEntry;
use Pushery\SQLens\Deploy\DebtLedger;
use Pushery\SQLens\Deploy\DebtLedgerRefusal;

/**
 * `get_debt_ledger` — the open ends a project already carries, before an agent adds more.
 *
 * ## Where the answer comes from
 *
 * The committed ledger file, and nothing else. No database table, no live catalog, and no write of
 * any kind: the account is a repository file precisely so a reviewer can see it in a diff, and a
 * tool that edited it from an agent loop would put a change into somebody's tree that nobody made.
 *
 * ## The determinism trap, solved here
 *
 * "Open for 94 days" is a sentence about a clock. Asked twice a day apart, a tool that measured
 * against `now()` gives two different answers about an unchanged file — which makes the output
 * impossible to compare between runs and impossible to hold with a golden test.
 *
 * So the reference date is an ARGUMENT. When the caller does not name one, it is derived from the
 * ledger itself — the newest `first_seen` it holds — rather than from the clock. Either way the
 * date used is IN the answer, so a reader can tell what "94 days" was counted from.
 *
 * ## Why a missing ledger is not an empty list
 *
 * "This project has no debt account" and "this project owes nothing" are different sentences, and
 * only one of them is good news. An empty list would be read as the second, so the absence is
 * reported as `undetermined` with its reason — as data an agent can act on rather than as an error
 * frame, because nothing failed.
 */
#[Name('get_debt_ledger')]
final class GetDebtLedgerTool extends SqlensTool
{
    protected string $description = 'Lists the migration debts a project has recorded: what was left half-done, when it was first seen, and how old it is. Reads the committed ledger file — no database, no writes.';

    public function mutating(): bool
    {
        return false;
    }

    /**
     * Dependencies arrive as ARGUMENTS, not through a constructor.
     *
     * The registry builds a tool with `new` — it holds instances so that "what a tool is" is decided
     * in one place — and the SDK invokes `handle` through the container, which resolves a method's
     * parameters. So the container still supplies the project root and the filesystem, and the tool
     * stays constructible without one. A constructor with container defaults would be a second way
     * to build the same object, and the two would disagree the day one of them was updated.
     */
    public function handle(Request $request, Repository $config, ProjectManifest $manifest, Filesystem $files): Response
    {
        // Validated here rather than trusted from the published schema: the SDK publishes
        // `inputSchema` and checks nothing against it on the way in.
        $validated = $this->validated($request);

        $configured = $config->get('sqlens.deploy.debt.path');
        $path = is_string($configured) && $configured !== '' ? $configured : DebtLedger::DEFAULT_PATH;
        $ledger = DebtLedger::load($files, $manifest->root().'/'.$path);

        if (! $ledger->isUsable()) {
            // Present and unreadable is a CONTENT problem in a specific line, and it is a different
            // thing to go and fix from an absent file. Both are undetermined; neither is "no debts".
            return ToolAnswer::undetermined(
                $ledger->refusal instanceof DebtLedgerRefusal
                    ? $ledger->refusal->detail
                    : 'the debt account could not be read',
                ['path' => $path],
            )->toResponse();
        }

        if (! $ledger->wasPresent()) {
            return ToolAnswer::undetermined(
                'no debt account exists at '.$path.' — that is not the same as owing nothing, '
                .'and it usually means the project has not adopted the account yet',
                ['path' => $path],
            )->toResponse();
        }

        $asOf = $this->referenceDate($validated, $ledger);
        $reference = new DateTimeImmutable($asOf.' 00:00:00', new DateTimeZone('UTC'));

        $rows = [];

        foreach ($ledger->entries as $entry) {
            $age = DebtAge::between($entry->firstSeen, $reference);
            $rows[] = ['entry' => $entry, 'age' => $age->isKnown() ? (int) $age->days() : null];
        }

        $rows = $this->narrowed($rows, $validated);

        // Oldest first, then by identity. A tie broken by file order would move the moment somebody
        // reordered the ledger, and two runs over one project would diff against each other.
        usort($rows, static fn (array $a, array $b): int => ($b['age'] ?? -1) <=> ($a['age'] ?? -1)
            ?: strcmp($a['entry']->id, $b['entry']->id));

        $total = count($rows);
        $offset = is_int($validated['offset'] ?? null) ? $validated['offset'] : 0;
        $limit = is_int($validated['limit'] ?? null) ? $validated['limit'] : $this->maxFindings($config);
        $page = array_slice($rows, $offset, $limit);

        return ToolAnswer::of([
            'path' => $path,
            // The date the ages were counted from, always. Without it "94 days" is a number nobody
            // can reproduce.
            'as_of' => $asOf,
            'total' => $total,
            'returned' => count($page),
            // Crossing the ceiling is REPORTED. A quiet truncation reads exactly like a project
            // with fewer open ends than it has.
            'truncated' => $offset + count($page) < $total,
            'debts' => array_map(
                static fn (array $row): array => [...$row['entry']->toArray(), 'age_days' => $row['age']],
                $page,
            ),
        ], sprintf('%d debt(s) recorded, %d returned, counted from %s.', $total, count($page), $asOf))->toResponse();
    }

    /** @return array<string, list<string>> */
    public function rules(): array
    {
        return [
            'min_age_days' => ['sometimes', 'integer', 'min:0', 'max:100000'],
            // Patterned rather than open: a debt kind is a lowercase identifier the rules produce
            // (`not_valid_constraint`, `invalid_index`). Deliberately not an `in:` list — the kinds
            // come from the rules, and a set frozen here would be a second source that drifts.
            'kind' => ['sometimes', 'string', 'max:64', 'regex:/^[a-z0-9_]+$/'],
            'as_of' => ['sometimes', 'string', 'date_format:Y-m-d'],
            'limit' => ['sometimes', 'integer', 'min:1', 'max:500'],
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
            'min_age_days' => $schema->integer()->description('Only debts at least this many days old.'),
            'kind' => $schema->string()->description('Only debts of this kind, for example "not_valid_constraint".'),
            'as_of' => $schema->string()->description('The UTC date (YYYY-MM-DD) ages are counted from. Defaults to the newest entry in the ledger, never to the current time, so two runs over one file agree.'),
            'limit' => $schema->integer()->description('At most this many debts in one answer.'),
            'offset' => $schema->integer()->description('Skip this many debts, for paging through a long account.'),
        ];
    }

    /**
     * The date ages are counted from.
     *
     * Never `now()`. A caller may name one; otherwise it is the newest `first_seen` the ledger
     * holds, which is a property of the FILE and therefore the same on every machine and in every
     * run. An empty ledger has no date to derive, and the epoch is used — every age is then zero,
     * which is honest for a file with nothing in it.
     *
     * @param  array<string, mixed>  $validated
     */
    private function referenceDate(array $validated, DebtLedger $ledger): string
    {
        if (is_string($validated['as_of'] ?? null)) {
            return $validated['as_of'];
        }

        $newest = '1970-01-01';

        foreach ($ledger->entries as $entry) {
            if (strcmp($entry->firstSeen, $newest) > 0) {
                $newest = $entry->firstSeen;
            }
        }

        return $newest;
    }

    /**
     * The rows a caller asked for.
     *
     * @param  list<array{entry: DebtEntry, age: int|null}>  $rows
     * @param  array<string, mixed>  $validated
     * @return list<array{entry: DebtEntry, age: int|null}>
     */
    private function narrowed(array $rows, array $validated): array
    {
        $minimum = $validated['min_age_days'] ?? null;
        $kind = $validated['kind'] ?? null;

        return array_values(array_filter($rows, static function (array $row) use ($minimum, $kind): bool {
            // An age this build could not read is NOT filtered out by a minimum: the entry exists
            // and is owed, and hiding it because its date is unreadable would answer a question
            // about age by removing the evidence.
            if (is_int($minimum) && $row['age'] !== null && $row['age'] < $minimum) {
                return false;
            }

            return ! is_string($kind) || $row['entry']->kind === $kind;
        }));
    }

    /** The project's ceiling on how much one answer may carry. */
    private function maxFindings(Repository $config): int
    {
        $configured = $config->get('sqlens.agent.mcp.max_findings');

        return is_int($configured) && $configured >= 1 && $configured <= ConfigSchema::MCP_MAX_FINDINGS_CEILING
            ? $configured
            : 200;
    }
}
