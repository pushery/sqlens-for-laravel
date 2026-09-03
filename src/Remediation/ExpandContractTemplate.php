<?php

declare(strict_types=1);

namespace Pushery\SQLens\Remediation;

use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Rules\RuleEvidence;
use Pushery\SQLens\Rules\RuleEvidenceEntry;

/**
 * The sequence that turns a breaking schema change into four ordinary ones — and the reference the
 * other multi-step strategies are shaped after.
 *
 * ## Why it is four phases and why the middle two are not statements
 *
 * A narrowing, a rename, a retyping: each is one statement that breaks every application version
 * still running against the old shape. The fix is not a better statement, it is a different SHAPE of
 * change — add the new thing beside the old one, move the data, move the readers and writers, and
 * only then remove what nobody uses any more.
 *
 * Two of those four phases are not SQL at all. The backfill is a job because it is unbounded in
 * time, and the dual-write window is a decision a person makes about releases. A template that
 * emitted only the two statements would be a template that shipped the dangerous half: the second
 * `ALTER` is safe exactly and only because the window before it happened.
 *
 * ## Why it is driver-neutral, and what that costs
 *
 * `ADD COLUMN` and `DROP COLUMN` are the same statement on PostgreSQL and MySQL, so this class
 * imports no driver and an architecture test holds it to that. It does NOT mean expand/contract is
 * engine-independent in general — a sequence that needed an engine-specific statement would take it
 * from that engine's own namespace rather than growing a `match` here. This one does not need one,
 * which is a measurement rather than an assumption.
 *
 * ## Why so much of it stays a placeholder
 *
 * The new column's name and type are DECISIONS, not facts a linter can read: they do not exist in
 * the statement being fixed. Filling them would mean inventing a schema. What the template
 * contributes is the ORDER and the gate between phases — which is the part people get wrong, and
 * the part no amount of name-filling would supply.
 *
 * ## What it deliberately does not carry
 *
 * The backfill's own recipe. Batching is its own strategy with its own template, and restating it
 * here would create a second definition free to drift from the first — with each looking correct
 * alone. Step two names the job and points at that strategy; it carries no SQL.
 *
 * ## It renders; it never runs
 *
 * A sequence spanning two releases is not something any tool could apply. That is the clearest case
 * in the package for material over automation: the gate in the middle is a human decision, and a
 * tool that skipped it would produce exactly the outage the sequence exists to prevent.
 */
final readonly class ExpandContractTemplate
{
    /**
     * The word an unfinished expand/contract is filed under in the ledger.
     *
     * It lives HERE, on the engine-neutral sequence, and not on the rule that reports it — because
     * both engines' rules file under the same word, and the ledger has to see ONE account for one
     * open end. Put on either rule, the other would have to reach across the driver boundary to
     * read it, or spell it a second time and quietly open a second account.
     *
     * Stable and machine-facing: it is part of an entry's derived identity, so renaming it renames
     * every debt of this kind and restarts all their ages at zero.
     */
    public const string DEBT_KIND = 'expand_without_contract';

    /** The key prefix every note, precondition and verification string of this template lives under. */
    private const string LANG = 'sqlens::messages.remediation.expand_contract.';

    /**
     * The shipped evidence register, so the CALLING rule's citation can be resolved here.
     *
     * The lookup sits in the template rather than in the rule, and that placement is enforced: a
     * rule class must not name this register at all, because a verdict that consulted a citation
     * would be deciding safety from a link. The guard caught exactly that when this template first
     * took its references as an argument and the rule did the lookup — right in spirit, wrong in
     * place, and the same shape both driver templates already use.
     */
    private RuleEvidence $evidence;

    public function __construct(?RuleEvidence $evidence = null)
    {
        $this->evidence = $evidence ?? RuleEvidence::bundled();
    }

    /**
     * The four-phase sequence for a change that would break a running old version.
     *
     * @param  array<string, string>  $context  placeholder values the CALLER measured — typically
     *                                          just the table and the old column, because
     *                                          everything else in the plan is a name that does not
     *                                          exist yet
     * @param  ?DowntimeClass  $downtimeClass  the class the CALLING rule carries or derived. Nullable
     *                                         because a rule that DERIVES its class per statement can
     *                                         reach a statement whose class the matrix could not
     *                                         settle — and the staged swap is the right plan either
     *                                         way, so withholding it there would punish the harder
     *                                         case. A null travels through as an absent field rather
     *                                         than as a guessed class.
     */
    public function payload(array $context, string $ruleId, ?DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: array_map(
                static fn (RemediationStep $step): RemediationStep => $step->filled($context),
                [
                    // 1 — EXPAND. Additive, nullable, no default: on PostgreSQL 11+ and MySQL 8+
                    // that is a metadata change rather than a rewrite, which is what lets the first
                    // phase ship in an ordinary deploy.
                    new RemediationStep(
                        order: 1,
                        kind: RemediationStepKind::MigrationStatement,
                        noteKey: self::LANG.'expand',
                        sqlTemplate: 'ALTER TABLE {{table}} ADD COLUMN {{new_column}} {{new_type}} NULL',
                    ),
                    // 2 — BACKFILL. A job, because the work is unbounded in time and a migration
                    // that holds a transaction open for it is the incident. No SQL here: the recipe
                    // belongs to the batching strategy, and a copy would be free to drift from it.
                    new RemediationStep(
                        order: 2,
                        kind: RemediationStepKind::QueuedJob,
                        noteKey: self::LANG.'backfill',
                    ),
                    // 3 — DUAL WRITE. The phase that makes phase four safe, and the only one that is
                    // not a change to the schema at all.
                    new RemediationStep(
                        order: 3,
                        kind: RemediationStepKind::ManualGate,
                        noteKey: self::LANG.'dual_write',
                    ),
                    // 4 — CONTRACT. A separate migration in a LATER release, never this one.
                    new RemediationStep(
                        order: 4,
                        kind: RemediationStepKind::SeparateMigration,
                        noteKey: self::LANG.'contract',
                        sqlTemplate: 'ALTER TABLE {{table}} DROP COLUMN {{old_column}}',
                    ),
                ],
            ),
            strategy: RemediationStrategy::ExpandContract,
            ruleId: $ruleId,
            downtimeClass: $downtimeClass,
            preconditions: [
                self::LANG.'precondition.no_old_version_running',
                self::LANG.'precondition.release_boundary_available',
            ],
            verification: self::LANG.'verification',
            // The addresses belong to whichever rule handed the statement over — this sequence is
            // neutral and has no citation of its own to restate.
            references: array_map(
                static fn (RuleEvidenceEntry $entry): string => $entry->url,
                $this->evidence->for($ruleId),
            ),
        );
    }

    /**
     * The CONTRACT half alone, for a sequence that already expanded and back-filled.
     *
     * The debt rule that reports an unfinished expand/contract is not a complaint about the expand:
     * adding the column and filling it was the right move, and it already happened. So the material
     * is one statement, not four. Handing over the whole sequence here would tell somebody to add a
     * column that is already there, in a migration they are not allowed to edit any more.
     *
     * ⚠️ **`{{old_column}}` stays a placeholder, and that is the honest answer rather than a gap.**
     * Which column the new one replaced is a DECISION — this class says so about itself at the top —
     * and the rule that produces this payload deliberately never guesses it: the source column sits
     * inside the expression on the right of the back-fill, and lifting it out would mean parsing
     * expressions in the layer built to be free of grammar. A filled-in wrong name would read as
     * decided; an unfilled one reads as a question for the person who knows the answer.
     *
     * @param  array<string, string>  $context  the table and the new column the RUN measured
     */
    public function forPendingContract(array $context, string $ruleId, ?DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: array_map(
                static fn (RemediationStep $step): RemediationStep => $step->filled($context),
                [
                    new RemediationStep(
                        order: 1,
                        kind: RemediationStepKind::SeparateMigration,
                        noteKey: self::LANG.'contract_only',
                        sqlTemplate: 'ALTER TABLE {{table}} DROP COLUMN {{old_column}}',
                    ),
                    new RemediationStep(
                        order: 2,
                        kind: RemediationStepKind::ManualGate,
                        noteKey: self::LANG.'debt_until_contracted',
                    ),
                ],
            ),
            strategy: RemediationStrategy::ExpandContract,
            ruleId: $ruleId,
            downtimeClass: $downtimeClass,
            // Only the one that decides whether the drop is safe. The release-boundary precondition
            // belongs to the full sequence: by the time this payload is produced, that boundary is
            // behind the reader rather than ahead of them.
            preconditions: [self::LANG.'precondition.no_old_version_running'],
            verification: self::LANG.'verification',
            references: array_map(
                static fn (RuleEvidenceEntry $entry): string => $entry->url,
                $this->evidence->for($ruleId),
            ),
            debtKind: self::DEBT_KIND,
        );
    }
}
