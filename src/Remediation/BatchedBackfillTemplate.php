<?php

declare(strict_types=1);

namespace Pushery\SQLens\Remediation;

use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Rules\RuleEvidence;
use Pushery\SQLens\Rules\RuleEvidenceEntry;

/**
 * The one batch recipe in this package — the backfill moved out of the migration and into a job
 * that can be paused, resumed, and run at a speed the database survives.
 *
 * ## Why it exists once
 *
 * Expand/contract needs a backfill. So does an unbounded mass write. So will the next multi-step
 * strategy that has to move data. Each of them restating a chunking loop would create definitions
 * free to drift apart — with every copy looking correct on its own, and only the database noticing
 * that one of them pages by `OFFSET`. So the recipe lives here and the others point at it.
 *
 * ## Keyset paging, and why `OFFSET` is the wrong answer
 *
 * `OFFSET n` makes the server walk and discard n rows before returning anything, so the cost of
 * batch number k grows with k: the last batch of a long backfill is the most expensive one, at
 * precisely the moment somebody has stopped watching. Paging by the last key seen is flat — every
 * batch is an index seek — and it survives an interruption, because the resume point is a value
 * rather than a position in a result set that has since changed.
 *
 * ## What it will not decide for you
 *
 * The batch size and the pause stay placeholders. They are the two knobs that decide whether the
 * backfill is invisible or is itself the incident, and the right values depend on the row width,
 * the replica lag budget and the traffic pattern — none of which are in the statement. SQLens can
 * estimate a row COUNT from catalog statistics, and that estimate is allowed to raise a finding's
 * severity; it is never allowed to become a number in a recipe, because a payload that filled in a
 * batch size would be a guess wearing the face of a measurement.
 *
 * ## The honesty this template inherits
 *
 * The rules that hand statements over here are heuristics: what they can see is that a write
 * carries no bound, and what they cannot see is how many rows that means. A hundred rows and a
 * hundred million produce identical SQL. The payload repeats that framing rather than presenting a
 * confident plan for a problem nobody has measured.
 *
 * ## It renders; it never runs
 *
 * The job is a SNIPPET — a string in a report. Nothing here writes a file, registers a job, or
 * touches a queue. An agent creates the class; a later `sqlens:lint` says whether the migration
 * stopped doing the work itself.
 */
final readonly class BatchedBackfillTemplate
{
    /** The key prefix every note, precondition and verification string of this template lives under. */
    private const string LANG = 'sqlens::messages.remediation.batched_backfill.';

    /**
     * The job skeleton, as it appears in a report.
     *
     * Keyset paging over the primary key, a bounded batch, and a pause between batches — the three
     * properties that separate a backfill from an outage. The two numbers are placeholders on
     * purpose; see the class note.
     */
    private const string JOB_SNIPPET = <<<'PHP'
        // app/Jobs/BackfillTable.php — queued, so the migration stays fast.
        public function handle(): void
        {
            $lastId = 0;

            do {
                $ids = DB::table('{{table}}')
                    ->where('id', '>', $lastId)   // keyset paging: flat cost, resumable
                    ->orderBy('id')
                    ->limit({{batch_size}})
                    ->pluck('id');

                if ($ids->isEmpty()) {
                    return;
                }

                DB::table('{{table}}')->whereIn('id', $ids)->update([/* the backfill */]);

                $lastId = $ids->last();

                usleep({{pause_microseconds}});   // give replicas and other traffic room
            } while (true);
        }
        PHP;

    /**
     * The shipped evidence register, so the CALLING rule's citation can be resolved here.
     *
     * A rule class must not name this register — a verdict that consulted a citation would be
     * deciding safety from a link — so the lookup lives in every template rather than in any rule.
     */
    private RuleEvidence $evidence;

    public function __construct(?RuleEvidence $evidence = null)
    {
        $this->evidence = $evidence ?? RuleEvidence::bundled();
    }

    /**
     * The batching sequence for a write that nothing bounds.
     *
     * ## Why the timeout preamble is step one rather than step three
     *
     * The ticket listed it last. It leads here for the same reason it leads in the concurrent-index
     * sequence: a session setting that arrives after the work it is supposed to bound has bounded
     * nothing. The difference worth stating is what the setting should BE — a job's statement
     * timeout is sized to ONE BATCH, not to a whole migration, and a value carried over from a
     * migration preamble will abort a backfill that was working perfectly.
     *
     * @param  array<string, string>  $context  placeholder values the caller measured — the table,
     *                                          and nothing else: the batch size and the pause are
     *                                          decisions rather than facts
     */
    public function payload(array $context, string $ruleId, DowntimeClass $downtimeClass): RemediationPayload
    {
        return $this->build($this->batchingSteps(), $context, $ruleId, $downtimeClass);
    }

    /**
     * The same batching sequence, opened by the SPLIT — for a write that shares a transaction with a
     * schema change on the table it writes.
     *
     * The extra step is not decoration and it is not optional. Batching a write that still sits
     * inside the schema change's transaction fixes nothing: the exclusive lock is held until the
     * transaction commits, so every batch runs under it and the pauses between them are pauses
     * spent HOLDING the lock — a slower outage rather than a shorter one. The separation has to
     * come first, and it is the one step whose absence turns the rest of the recipe into a
     * pessimization.
     *
     * An entry point rather than a template of its own, deliberately. What follows the split is the
     * same recipe, and a second copy of a chunking loop is exactly the drift the class note
     * describes — the difference here is one step at the front, not a different way to move data.
     *
     * @param  array<string, string>  $context  placeholder values the caller measured
     */
    public function forSchemaChangedTable(array $context, string $ruleId, DowntimeClass $downtimeClass): RemediationPayload
    {
        return $this->build(
            [
                new RemediationStep(
                    order: 1,
                    kind: RemediationStepKind::SeparateMigration,
                    noteKey: self::LANG.'split_from_the_schema_change',
                ),
                ...array_map(
                    static fn (RemediationStep $step): RemediationStep => new RemediationStep(
                        order: $step->order + 1,
                        kind: $step->kind,
                        noteKey: $step->noteKey,
                        sqlTemplate: $step->sqlTemplate,
                        laravelSnippet: $step->laravelSnippet,
                        withinTransaction: $step->withinTransaction,
                    ),
                    $this->batchingSteps(),
                ),
            ],
            $context,
            $ruleId,
            $downtimeClass,
        );
    }

    /**
     * The recipe itself, written once — the three properties that separate a backfill from an outage.
     *
     * @return list<RemediationStep>
     */
    private function batchingSteps(): array
    {
        return [
            new RemediationStep(
                order: 1,
                kind: RemediationStepKind::SessionSetting,
                noteKey: self::LANG.'timeout_per_batch',
            ),
            new RemediationStep(
                order: 2,
                kind: RemediationStepKind::QueuedJob,
                noteKey: self::LANG.'job',
                laravelSnippet: self::JOB_SNIPPET,
            ),
            new RemediationStep(
                order: 3,
                kind: RemediationStepKind::ManualGate,
                noteKey: self::LANG.'resume_criterion',
            ),
        ];
    }

    /**
     * @param  list<RemediationStep>  $steps
     * @param  array<string, string>  $context
     */
    private function build(array $steps, array $context, string $ruleId, DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: array_map(
                static fn (RemediationStep $step): RemediationStep => $step->filled($context),
                $steps,
            ),
            strategy: RemediationStrategy::BatchedBackfill,
            ruleId: $ruleId,
            downtimeClass: $downtimeClass,
            preconditions: [
                self::LANG.'precondition.orderable_key',
                self::LANG.'precondition.idempotent_write',
                self::LANG.'precondition.size_is_an_estimate',
            ],
            verification: self::LANG.'verification',
            references: array_map(
                static fn (RuleEvidenceEntry $entry): string => $entry->url,
                $this->evidence->for($ruleId),
            ),
        );
    }
}
