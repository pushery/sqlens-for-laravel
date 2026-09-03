<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Remediation;

use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Remediation\RemediationStep;
use Pushery\SQLens\Remediation\RemediationStepKind;
use Pushery\SQLens\Remediation\RemediationStrategy;
use Pushery\SQLens\Rules\RuleEvidence;
use Pushery\SQLens\Rules\RuleEvidenceEntry;

/**
 * Splitting a mixed migration so each half can fail on its own — MySQL's reason, not PostgreSQL's.
 *
 * ## Why this is not the PostgreSQL split template with a different name
 *
 * `TransactionSplitTemplate` argues from LOCKS: PostgreSQL holds every lock a transaction takes
 * until it commits, so bundling three tables locks the first for the duration of all three. On MySQL
 * that argument does not exist. Laravel's MySQL grammar reports `supportsSchemaTransactions() ===
 * false`, so the migrator never opens a transaction — there is nothing to hold a lock across.
 *
 * The MySQL hazard is the opposite fact: **every DDL statement causes an implicit commit**. The
 * schema change is already committed by the time the data write runs, so a write that fails leaves
 * the migration half applied — schema changed, data not — with nothing to roll back. `down()` becomes
 * the only way out, and it has to undo a state nobody planned for.
 *
 * Same words, "split it up"; different reason, different consequence, and a reader pointed at the
 * lock argument would go looking for a lock that is not there. Two templates is the honest count.
 *
 * ## It carries no SQL
 *
 * The statements are already written; what is wrong is which FILE they are in. Emitting them again
 * with different boundaries would mean this template reproducing somebody's migration, and the one
 * thing it cannot know — what the data write should do if the schema change is already live — is
 * exactly the thing the split exists to force somebody to think about.
 *
 * ## It renders; it never runs
 */
final readonly class AtomicitySplitTemplate
{
    /** The key prefix every note, precondition and verification string of this template lives under. */
    private const string LANG = 'sqlens::messages.remediation.atomicity_split.';

    /** The shipped evidence register — a rule class must not name it, so the lookup lives here. */
    private RuleEvidence $evidence;

    public function __construct(?RuleEvidence $evidence = null)
    {
        $this->evidence = $evidence ?? RuleEvidence::bundled();
    }

    /**
     * The split: schema in one migration, data in the next, and a name for what the gap between
     * them means.
     *
     * The middle step is the one people leave out, and it is the whole reason the split is not just
     * tidiness. Between the two migrations the schema is live and the data is not — so the running
     * application meets a column that exists and is empty, and whether that is harmless or an
     * incident is a question about the application, not about the migration.
     */
    public function payload(string $ruleId, ?DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: [
                new RemediationStep(
                    order: 1,
                    kind: RemediationStepKind::SeparateMigration,
                    noteKey: self::LANG.'schema_first',
                ),
                new RemediationStep(
                    order: 2,
                    kind: RemediationStepKind::ManualGate,
                    noteKey: self::LANG.'mind_the_gap',
                ),
                new RemediationStep(
                    order: 3,
                    kind: RemediationStepKind::SeparateMigration,
                    noteKey: self::LANG.'data_second',
                ),
            ],
            strategy: RemediationStrategy::TransactionSplit,
            ruleId: $ruleId,
            downtimeClass: $downtimeClass,
            preconditions: [
                self::LANG.'precondition.ddl_commits_implicitly',
                self::LANG.'precondition.down_must_match_the_halves',
            ],
            verification: self::LANG.'verification',
            references: array_map(
                static fn (RuleEvidenceEntry $entry): string => $entry->url,
                $this->evidence->for($ruleId),
            ),
        );
    }
}
