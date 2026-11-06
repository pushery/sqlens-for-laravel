<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Remediation;

use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Remediation\RemediationStep;
use Pushery\SQLens\Remediation\RemediationStepKind;
use Pushery\SQLens\Remediation\RemediationStrategy;
use Pushery\SQLens\Rules\RuleEvidence;
use Pushery\SQLens\Rules\RuleEvidenceEntry;

/**
 * Reaching the new column type without the pass over every row that `ALTER COLUMN … TYPE` makes.
 *
 * ## What it is, and what it is a special case of
 *
 * Structurally this is expand/contract. What makes it its own template rather than a caller of that
 * one is the step in the middle: a retyped column usually carries an index or a constraint, and the
 * new column has to get its own before anything reads it — built concurrently, or the plan trades a
 * rewrite for a blocking index build and nobody is better off.
 *
 * ## Both columns are written before the backfill starts
 *
 * The first release writes the new column beside the old one and still reads the old one. Only then
 * does the backfill run, so a row written while it runs reaches the new column either way, and the
 * release that reads the new column finds every row filled. The other order leaves the rows that an
 * old release writes behind the job without a value, and nothing later in the plan fills them.
 *
 * It is PostgreSQL's because the PROBLEM is: whether a given type change rewrites the table is a
 * PostgreSQL question answered by a PostgreSQL matrix, and a `USING` expression forces the rewrite
 * whatever the types are.
 *
 * ## It links; it does not restate
 *
 * The backfill points at the batching strategy and the index step points at the concurrent build.
 * Neither carries SQL of its own. Two copies of a chunking loop, or of a concurrent index build,
 * drift the first time either is tuned — and both copies look correct alone.
 *
 * ## The swap is two statements, not one
 *
 * PostgreSQL does not accept a `DROP COLUMN` and a `RENAME COLUMN` in one `ALTER TABLE`, so folding
 * the contract phase into a single step would hand somebody a line the server rejects. Both are
 * metadata-only, both belong in the same later migration, and they are two steps because they are
 * two statements.
 *
 * ## The new column is analyzed before anything reads it
 *
 * A column added with `ADD COLUMN` has no planner statistics, and the backfill writes its values
 * without collecting any. Autovacuum analyzes the table once the backfill's updates cross its
 * threshold, on its own schedule and not at all where it is switched off, so the plan runs the
 * `ANALYZE` itself, after the indexes and before the release that reads the column. It analyzes the
 * whole table: with a column list, `ANALYZE` skips the expressions of an expression index. The swap
 * keeps what it collected: the statistics belong to the column, and the rename does not replace it.
 *
 * ## It renders; it never runs
 *
 * A sequence spanning several releases is not something a tool could apply, and its gates are
 * human decisions about deploys.
 */
final readonly class RewriteAvoidanceTemplate
{
    /** The key prefix every note, precondition and verification string of this template lives under. */
    private const string LANG = 'sqlens::messages.remediation.rewrite_avoidance.';

    /** The shipped evidence register — a rule class must not name it, so the lookup lives here. */
    private RuleEvidence $evidence;

    public function __construct(?RuleEvidence $evidence = null)
    {
        $this->evidence = $evidence ?? RuleEvidence::bundled();
    }

    /**
     * The staged retyping.
     *
     * @param  array<string, string>  $context  placeholder values the caller measured — the table and
     *                                          the old column. The new column's name is a decision
     *                                          and stays visible, and so does the target type: the
     *                                          statement names one, but writing it into the plan
     *                                          would present the rewriting change as the destination
     *                                          when the whole point is to reach it another way.
     */
    public function payload(array $context, string $ruleId, DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: array_map(
                static fn (RemediationStep $step): RemediationStep => $step->filled($context),
                [
                    // 1 — the new column, additive and nullable: a metadata change on PostgreSQL 11+.
                    new RemediationStep(
                        order: 1,
                        kind: RemediationStepKind::MigrationStatement,
                        noteKey: self::LANG.'add_column',
                        sqlTemplate: 'ALTER TABLE {{table}} ADD COLUMN {{new_column}} {{new_type}} NULL',
                    ),
                    // 2 — a release that writes both columns and still reads the old one, so every
                    // row written from here on reaches the new column and the backfill can finish.
                    new RemediationStep(
                        order: 2,
                        kind: RemediationStepKind::ManualGate,
                        noteKey: self::LANG.'dual_write',
                    ),
                    // 3 — the backfill, by reference. No SQL: the recipe belongs to the batching
                    // strategy and a copy would be free to drift from it.
                    new RemediationStep(
                        order: 3,
                        kind: RemediationStepKind::QueuedJob,
                        noteKey: self::LANG.'backfill',
                    ),
                    // 4 — the step that distinguishes this from a plain expand/contract, also by
                    // reference: an index or constraint the old column carried has to exist on the
                    // new one before anything reads it, built concurrently.
                    new RemediationStep(
                        order: 4,
                        kind: RemediationStepKind::SeparateMigration,
                        noteKey: self::LANG.'carry_over_indexes',
                        withinTransaction: false,
                    ),
                    // 5 — the statistics. ADD COLUMN gives the new column none, and an expression
                    // index from step 4 has none either until the table is analyzed as a whole.
                    new RemediationStep(
                        order: 5,
                        kind: RemediationStepKind::SeparateMigration,
                        noteKey: self::LANG.'analyze_new_column',
                        sqlTemplate: 'ANALYZE {{table}}',
                    ),
                    // 6 — the readers move, and the window that makes the swap safe begins.
                    new RemediationStep(
                        order: 6,
                        kind: RemediationStepKind::ManualGate,
                        noteKey: self::LANG.'switch_reads',
                    ),
                    // 7 — contract. Metadata-only, in a later release.
                    new RemediationStep(
                        order: 7,
                        kind: RemediationStepKind::SeparateMigration,
                        noteKey: self::LANG.'drop_old_column',
                        sqlTemplate: 'ALTER TABLE {{table}} DROP COLUMN {{old_column}}',
                    ),
                    // 8 — the rename, which PostgreSQL will not accept in the same ALTER TABLE as
                    // the drop. Two statements, so two steps.
                    new RemediationStep(
                        order: 8,
                        kind: RemediationStepKind::MigrationStatement,
                        noteKey: self::LANG.'rename_into_place',
                        sqlTemplate: 'ALTER TABLE {{table}} RENAME COLUMN {{new_column}} TO {{old_column}}',
                    ),
                ],
            ),
            strategy: RemediationStrategy::RewriteAvoidance,
            ruleId: $ruleId,
            downtimeClass: $downtimeClass,
            preconditions: [
                self::LANG.'precondition.values_fit_the_new_type',
                self::LANG.'precondition.no_old_version_running',
            ],
            verification: self::LANG.'verification',
            references: array_map(
                static fn (RuleEvidenceEntry $entry): string => $entry->url,
                $this->evidence->for($ruleId),
            ),
        );
    }
}
