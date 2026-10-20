<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Remediation;

use Pushery\SQLens\Drivers\Pgsql\Rules\Support\QuotedObjectName;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Remediation\RemediationStep;
use Pushery\SQLens\Remediation\RemediationStepKind;
use Pushery\SQLens\Remediation\RemediationStrategy;
use Pushery\SQLens\Remediation\RemediationSubject;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * The expand/contract sequence that widens a foreign-key column to the width of the key it
 * references.
 *
 * Two rules report such a column: `PG.L6.FK_NARROWER_THAN_KEY` for the shape, and
 * `PG.L5.FK_NEAR_CEILING` once the referenced key's sequence has nearly filled the column. One change
 * puts both right, so both hand out this one sequence rather than two copies free to drift apart.
 *
 * Every step is its own migration: add a `bigint` column beside the old one, backfill it from a job,
 * ship a release that writes both and reads the new one, move the constraint, and only then drop the
 * old column. `ALTER TABLE … ALTER COLUMN … TYPE bigint` reaches the same end state in one statement
 * and is named in a precondition rather than emitted: on PostgreSQL it rewrites every row under
 * `ACCESS EXCLUSIVE`, and the size at which that stops being acceptable is a fact about the table
 * nothing here can read.
 *
 * No downtime class and no step in a migration at hand: a state finding has no deploy to describe,
 * and its fix is a new migration.
 */
final readonly class ForeignKeyWideningTemplate
{
    /** The sequence for a table whose narrowing key stands alone on its constraint. */
    public function payload(string $ruleId, SchemaObject $object): RemediationPayload
    {
        // The table is a fact of the finding, quoted as PostgreSQL reads it. The key's own names stay
        // placeholders: the sequence is written once, for whichever of the table's narrowing keys the
        // reader widens.
        $context = ['table' => QuotedObjectName::of($object)];

        $steps = array_map(static fn (RemediationStep $step): RemediationStep => $step->filled($context), [
            new RemediationStep(
                order: 1,
                kind: RemediationStepKind::SeparateMigration,
                noteKey: 'sqlens::messages.remediation.expand_contract.expand',
                sqlTemplate: 'ALTER TABLE {{table}} ADD COLUMN {{new_column}} bigint',
            ),
            new RemediationStep(
                order: 2,
                kind: RemediationStepKind::QueuedJob,
                noteKey: 'sqlens::messages.remediation.expand_contract.backfill',
            ),
            new RemediationStep(
                order: 3,
                kind: RemediationStepKind::ManualGate,
                noteKey: 'sqlens::messages.remediation.expand_contract.dual_write',
            ),
            new RemediationStep(
                order: 4,
                kind: RemediationStepKind::SeparateMigration,
                noteKey: 'sqlens::messages.remediation.expand_contract.swap_the_key',
                // Two statements, one migration: a table with the constraint on neither column
                // accepts rows that reference nothing, and the width of that window is the whole risk
                // of this step. No RENAME here: on PostgreSQL that is its own form of ALTER TABLE.
                sqlTemplate: 'ALTER TABLE {{table}} DROP CONSTRAINT {{constraint}}; '
                    .'ALTER TABLE {{table}} ADD CONSTRAINT {{constraint}} '
                    .'FOREIGN KEY ({{new_column}}) REFERENCES {{referenced_table}} ({{referenced_column}})',
            ),
            new RemediationStep(
                order: 5,
                kind: RemediationStepKind::SeparateMigration,
                noteKey: 'sqlens::messages.remediation.expand_contract.contract',
                sqlTemplate: 'ALTER TABLE {{table}} DROP COLUMN {{old_column}}',
            ),
        ]);

        return new RemediationPayload(
            steps: $steps,
            strategy: RemediationStrategy::ExpandContract,
            ruleId: $ruleId,
            preconditions: [
                'sqlens::messages.remediation.expand_contract.precondition.in_place_rewrites_the_table',
                'sqlens::messages.remediation.expand_contract.precondition.no_old_version_running',
                'sqlens::messages.remediation.expand_contract.precondition.release_boundary_available',
            ],
            verification: 'sqlens::messages.remediation.expand_contract.verification',
            subject: RemediationSubject::SchemaObject,
        );
    }
}
