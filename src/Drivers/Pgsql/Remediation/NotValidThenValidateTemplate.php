<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Remediation;

use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Drivers\Pgsql\Rules\L2\ConstraintShape;
use Pushery\SQLens\Drivers\Pgsql\Rules\L4\ConstraintValidationPendingRule;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Remediation\RemediationStep;
use Pushery\SQLens\Remediation\RemediationStepKind;
use Pushery\SQLens\Remediation\RemediationStrategy;
use Pushery\SQLens\Rules\RuleEvidence;
use Pushery\SQLens\Rules\RuleEvidenceEntry;
use Pushery\SQLens\Rules\TouchedTables;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The safe sequences behind `ADD CONSTRAINT` — two of them, because PostgreSQL has two answers and
 * giving the wrong one is worse than giving none.
 *
 * ## The split, and why it is not a detail
 *
 * `NOT VALID` is accepted on a FOREIGN KEY and on a CHECK. It is **not** accepted on a PRIMARY KEY
 * or a UNIQUE constraint — those are implemented with an index, and the index has to exist before
 * the constraint can be promoted onto it. Material that recommended `NOT VALID` there would be
 * advice the server refuses, discovered at the moment somebody trusted it. So the shape is decided
 * once, by {@see ConstraintShape}, and both the rule's wording and this class's sequence read that
 * one decision.
 *
 * ## The step that is the whole point
 *
 * `ADD CONSTRAINT … NOT VALID` is correct and incomplete at the same moment. It applies to every
 * new row immediately and costs a brief metadata lock instead of a full-table scan — and it does
 * not hold for the rows that were already there until `VALIDATE CONSTRAINT` runs. Nothing breaks,
 * nothing is slow, and no error is raised, which is exactly why the second half is the one that
 * gets forgotten.
 *
 * A template that stopped after step one would therefore not be a shorter fix; it would be a way of
 * turning a visible problem into an invisible permanent one. So the second migration is a step, and
 * the payload NAMES the debt the gap between them opens — in the ledger's own word, read from
 * {@see ConstraintValidationPendingRule::DEBT_KIND} rather than spelled a second time here.
 *
 * ## What it can fill, and what it deliberately leaves standing
 *
 * The constraint name and the columns come from the classification. The TABLE does too — but only
 * when the statement names exactly one, and a foreign key names two: the altered table and the
 * referenced one, in the classifier's alphabetical order, which cannot say which is which. Rather
 * than pick the likelier of two, the placeholder stays visible. The definition (`FOREIGN KEY (…)
 * REFERENCES …`) is raw SQL that the canonical model does not carry at all, and reconstructing it
 * would be the invention this package refuses everywhere else.
 *
 * ## It renders; it never runs
 *
 * Nothing here executes anything, and no step names a path or a command. The payload is material an
 * agent applies, and a later `sqlens:lint` — plus `sqlens:predeploy`, which reads the catalog — is
 * what says the fix worked.
 */
final readonly class NotValidThenValidateTemplate
{
    /** The key prefix every note, precondition and verification string of this template lives under. */
    private const string LANG = 'sqlens::messages.remediation.constraint.';

    /**
     * The shipped evidence register, which is where this template's references come from.
     *
     * Not a URL constant: the register already holds the PostgreSQL anchor for the rule this fixes,
     * so a second address here could disagree with the rule's own citation in whichever direction
     * nobody reads. Resolved once per instance, the same way the rule base resolves its driver
     * notes.
     */
    private RuleEvidence $evidence;

    public function __construct(?RuleEvidence $evidence = null)
    {
        $this->evidence = $evidence ?? RuleEvidence::bundled();
    }

    /**
     * The sequence for THIS statement, chosen by the shape of the constraint it adds.
     *
     * One entry point rather than two public methods, because the choice is not the caller's to
     * make: a rule that picked the sequence itself would be the second reading this class exists to
     * prevent.
     */
    public function forConstraint(MigrationStatementView $statement, ConstraintShape $shape, string $ruleId, DowntimeClass $downtimeClass): RemediationPayload
    {
        return $shape === ConstraintShape::NotValidCapable
            ? $this->notValidThenValidate($statement, $ruleId, $downtimeClass)
            : $this->promoteFromIndex($statement, $shape, $ruleId, $downtimeClass);
    }

    /**
     * The SECOND half alone — for an open end the run found, where step one already happened.
     *
     * `ADD CONSTRAINT … NOT VALID` was the right thing to do, and the debt rule that reports this is
     * not a complaint about it: it is the account of a deliberate two-step sitting at step one. So
     * the material is one statement, not three. Handing over the whole sequence here would tell
     * somebody to add a constraint that is already there, on a file they are not allowed to edit.
     *
     * It carries the same `debtKind` the full sequence opens, which is what lets a reader join this
     * payload to the ledger entry that named the constraint.
     *
     * @param  array<string, string>  $context  the table and constraint the RUN measured — not this
     *                                          statement's own targets, because the finding is about
     *                                          a statement in an earlier migration
     */
    public function forPendingValidation(array $context, string $ruleId, DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: array_map(
                static fn (RemediationStep $step): RemediationStep => $step->filled($context),
                [
                    new RemediationStep(
                        order: 1,
                        kind: RemediationStepKind::SeparateMigration,
                        noteKey: self::LANG.'validate',
                        sqlTemplate: 'ALTER TABLE {{table}} VALIDATE CONSTRAINT {{constraint}}',
                    ),
                    new RemediationStep(
                        order: 2,
                        kind: RemediationStepKind::ManualGate,
                        noteKey: self::LANG.'debt_until_validated',
                    ),
                ],
            ),
            strategy: RemediationStrategy::NotValidThenValidate,
            ruleId: $ruleId,
            downtimeClass: $downtimeClass,
            preconditions: [self::LANG.'precondition.existing_rows_may_violate'],
            verification: self::LANG.'verification',
            references: $this->references($ruleId),
            debtKind: ConstraintValidationPendingRule::DEBT_KIND,
        );
    }

    /** FOREIGN KEY and CHECK: add unvalidated, validate later, and account for the gap between. */
    private function notValidThenValidate(MigrationStatementView $statement, string $ruleId, DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: $this->fill([
                new RemediationStep(
                    order: 1,
                    kind: RemediationStepKind::MigrationStatement,
                    noteKey: self::LANG.'add_not_valid',
                    sqlTemplate: 'ALTER TABLE {{table}} ADD CONSTRAINT {{constraint}} {{definition}} NOT VALID',
                ),
                new RemediationStep(
                    order: 2,
                    kind: RemediationStepKind::SeparateMigration,
                    noteKey: self::LANG.'validate',
                    sqlTemplate: 'ALTER TABLE {{table}} VALIDATE CONSTRAINT {{constraint}}',
                ),
                new RemediationStep(
                    order: 3,
                    kind: RemediationStepKind::ManualGate,
                    noteKey: self::LANG.'debt_until_validated',
                ),
            ], $statement),
            strategy: RemediationStrategy::NotValidThenValidate,
            ruleId: $ruleId,
            downtimeClass: $downtimeClass,
            preconditions: [
                self::LANG.'precondition.existing_rows_may_violate',
                self::LANG.'precondition.second_migration_is_planned',
            ],
            verification: self::LANG.'verification',
            references: $this->references($ruleId),
            // The account this advice deliberately opens, in the ledger's own word.
            debtKind: ConstraintValidationPendingRule::DEBT_KIND,
        );
    }

    /**
     * PRIMARY KEY and UNIQUE: build the index concurrently, then promote it onto the constraint.
     *
     * No debt kind, and that absence is a statement rather than an omission: this sequence closes
     * inside one deploy. What it can leave behind — an INVALID index from an interrupted build — is
     * the concurrent build's own leftover, which is why step one points at that sequence instead of
     * restating its cleanup here.
     */
    private function promoteFromIndex(MigrationStatementView $statement, ConstraintShape $shape, string $ruleId, DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: $this->fill([
                new RemediationStep(
                    order: 1,
                    kind: RemediationStepKind::SeparateMigration,
                    noteKey: self::LANG.'build_index_concurrently',
                    sqlTemplate: 'CREATE UNIQUE INDEX CONCURRENTLY {{index}} ON {{table}} ({{columns}})',
                    laravelSnippet: 'public $withinTransaction = false;',
                    withinTransaction: false,
                ),
                new RemediationStep(
                    order: 2,
                    kind: RemediationStepKind::MigrationStatement,
                    noteKey: self::LANG.'promote_index',
                    sqlTemplate: 'ALTER TABLE {{table}} ADD CONSTRAINT {{constraint}} '.$shape->promotionKeyword().' USING INDEX {{index}}',
                ),
                new RemediationStep(
                    order: 3,
                    kind: RemediationStepKind::ManualGate,
                    noteKey: self::LANG.'index_must_be_valid',
                ),
            ], $statement),
            strategy: RemediationStrategy::Concurrently,
            ruleId: $ruleId,
            downtimeClass: $downtimeClass,
            preconditions: [
                self::LANG.'precondition.no_duplicate_rows',
                self::LANG.'precondition.migrator_leaves_transaction',
            ],
            verification: self::LANG.'verification',
            references: $this->references($ruleId),
        );
    }

    /**
     * The sequence that makes `SET NOT NULL` skip its scan — the same trick, applied to a different
     * statement.
     *
     * `SET NOT NULL` proves no row is null by reading every one of them, under an ACCESS EXCLUSIVE
     * lock. Since PostgreSQL 12 it will instead TRUST a validated `CHECK (col IS NOT NULL)` and skip
     * the scan entirely — so the sequence is: add the check unvalidated, validate it under the
     * weaker lock, then set the column, then drop the check that has become redundant.
     *
     * It lives beside {@see notValidThenValidate()} rather than in a file of its own because it is
     * the same two moves in front of a third: a separate template would be a second place to keep
     * the `NOT VALID` reasoning in step with, and both copies would look correct alone.
     *
     * The constraint NAME stays a placeholder — it does not exist yet, and generating one would
     * make two runs over the same migration disagree about what to drop in step four.
     *
     * @param  array<string, string>  $context
     */
    public function forSetNotNull(array $context, string $ruleId, DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: $this->fillSteps([
                new RemediationStep(
                    order: 1,
                    kind: RemediationStepKind::MigrationStatement,
                    noteKey: self::LANG.'not_null_check',
                    sqlTemplate: 'ALTER TABLE {{table}} ADD CONSTRAINT {{constraint}} CHECK ({{column}} IS NOT NULL) NOT VALID',
                ),
                new RemediationStep(
                    order: 2,
                    kind: RemediationStepKind::SeparateMigration,
                    noteKey: self::LANG.'validate',
                    sqlTemplate: 'ALTER TABLE {{table}} VALIDATE CONSTRAINT {{constraint}}',
                ),
                new RemediationStep(
                    order: 3,
                    kind: RemediationStepKind::MigrationStatement,
                    noteKey: self::LANG.'set_not_null_trusts_it',
                    sqlTemplate: 'ALTER TABLE {{table}} ALTER COLUMN {{column}} SET NOT NULL',
                ),
                new RemediationStep(
                    order: 4,
                    kind: RemediationStepKind::MigrationStatement,
                    noteKey: self::LANG.'drop_the_now_redundant_check',
                    sqlTemplate: 'ALTER TABLE {{table}} DROP CONSTRAINT {{constraint}}',
                ),
            ], $context),
            strategy: RemediationStrategy::NotValidThenValidate,
            ruleId: $ruleId,
            downtimeClass: $downtimeClass,
            preconditions: [
                self::LANG.'precondition.no_null_rows',
                self::LANG.'precondition.second_migration_is_planned',
            ],
            verification: self::LANG.'verification',
            references: $this->references($ruleId),
            // The same account the constraint rule opens: between steps one and two the check does
            // not hold for rows that were already there, and that gap is what the ledger tracks.
            debtKind: ConstraintValidationPendingRule::DEBT_KIND,
        );
    }

    /**
     * The addresses behind this rule's advice, read from the register rather than restated.
     *
     * @return list<string>
     */
    private function references(string $ruleId): array
    {
        return array_map(
            static fn (RuleEvidenceEntry $entry): string => $entry->url,
            $this->evidence->for($ruleId),
        );
    }

    /**
     * Every step with its placeholders filled from the classified statement.
     *
     * @param  list<RemediationStep>  $steps
     * @return list<RemediationStep>
     */
    private function fill(array $steps, MigrationStatementView $statement): array
    {
        return $this->fillSteps($steps, $this->context($statement));
    }

    /**
     * Every step filled from a context the CALLER measured.
     *
     * The `SET NOT NULL` sequence needs a column, which is not one of this template's three
     * placeholders and is read by the rule that owns that statement — so the context arrives ready
     * rather than being derived a second time here.
     *
     * @param  list<RemediationStep>  $steps
     * @param  array<string, string>  $context
     * @return list<RemediationStep>
     */
    private function fillSteps(array $steps, array $context): array
    {
        return array_map(static fn (RemediationStep $step): RemediationStep => $step->filled($context), $steps);
    }

    /**
     * The placeholder values THIS statement carries — and only the ones it carries.
     *
     * Three deliberate absences, each of which leaves its placeholder visible rather than blank:
     *
     * - `{{table}}` on a foreign key. The statement names two tables and the classification sorts
     *   them alphabetically, so nothing here can say which one is being altered. Picking the first
     *   would be right most of the time and silently wrong the rest, which is the worst of the
     *   available failures.
     * - `{{definition}}`, always. `FOREIGN KEY (…) REFERENCES …` is raw SQL the canonical model does
     *   not carry, and rebuilding it from the classification would be inventing a statement.
     * - `{{index}}`, always. The index does not exist yet — its name is the reader's to choose, and
     *   a generated one would make two runs over the same migration disagree.
     *
     * @return array<string, string>
     */
    private function context(MigrationStatementView $statement): array
    {
        $context = [];

        $constraint = $statement->soleTarget(SchemaObjectType::Constraint);

        if ($constraint instanceof StatementTarget) {
            $context['constraint'] = $constraint->qualifiedName();
        }

        $tables = TouchedTables::of($statement);

        if (count($tables) === 1) {
            $context['table'] = $tables[0]->qualifiedName();
        }

        if ($statement->keyColumns !== []) {
            $context['columns'] = implode(', ', $statement->keyColumns);
        }

        return $context;
    }
}
