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
 * Giving each strong lock its own migration, so each is released before the next is taken.
 *
 * ## What the bundle costs, and why it is not the sum of the statements
 *
 * PostgreSQL holds every lock a transaction takes until it COMMITS. So a migration that alters
 * three tables in one transaction does not lock each for its own duration — it locks the first for
 * the duration of all three. Traffic to the table touched first queues behind the slowest operation
 * in the migration, which is a cost nothing in that statement hints at.
 *
 * ## The advice that would be wrong
 *
 * "Split everything" is not the fix, and a template that said so would make migrations worse.
 * Several `ALTER` clauses on the SAME table in one statement are ONE lock, not a bundle — splitting
 * those into separate migrations takes the same lock several times and lengthens the total. The
 * distinction is the whole content of the second step.
 *
 * ## It carries no SQL
 *
 * The statements are already written; what is wrong is how they are grouped. Emitting them again
 * with different boundaries would mean this template reproducing somebody's migration, and the one
 * thing it could get wrong — the order between the new files — is exactly what it cannot know.
 *
 * ## It renders; it never runs
 */
final readonly class TransactionSplitTemplate
{
    /** The key prefix every note, precondition and verification string of this template lives under. */
    private const string LANG = 'sqlens::messages.remediation.transaction_split.';

    /** The shipped evidence register — a rule class must not name it, so the lookup lives here. */
    private RuleEvidence $evidence;

    public function __construct(?RuleEvidence $evidence = null)
    {
        $this->evidence = $evidence ?? RuleEvidence::bundled();
    }

    /** The split. */
    public function payload(string $ruleId, DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: [
                new RemediationStep(
                    order: 1,
                    kind: RemediationStepKind::SeparateMigration,
                    noteKey: self::LANG.'one_migration_per_table',
                ),
                new RemediationStep(
                    order: 2,
                    kind: RemediationStepKind::ManualGate,
                    noteKey: self::LANG.'do_not_over_split',
                ),
                new RemediationStep(
                    order: 3,
                    kind: RemediationStepKind::ManualGate,
                    noteKey: self::LANG.'order_still_matters',
                ),
            ],
            strategy: RemediationStrategy::TransactionSplit,
            ruleId: $ruleId,
            downtimeClass: $downtimeClass,
            preconditions: [
                self::LANG.'precondition.no_all_or_nothing_requirement',
            ],
            verification: self::LANG.'verification',
            references: array_map(
                static fn (RuleEvidenceEntry $entry): string => $entry->url,
                $this->evidence->for($ruleId),
            ),
        );
    }
}
