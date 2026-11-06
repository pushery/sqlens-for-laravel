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
 * The statement as written, then an `ANALYZE` of its table in the same migration.
 *
 * For a change that costs the planner its statistics and rewrites nothing. `ALTER COLUMN … TYPE`
 * removes the column's statistics in every form, and the change adds nothing to the count of
 * modified rows that prompts autovacuum to analyze the table, so the migration collects them
 * itself. The step analyzes the whole table, the form the finding names.
 */
final readonly class AnalyzeAfterTemplate
{
    /** The key prefix every note and the verification string of this template live under. */
    private const string LANG = 'sqlens::messages.remediation.analyze_after.';

    /** The shipped evidence register — a rule class must not name it, so the lookup lives here. */
    private RuleEvidence $evidence;

    public function __construct(?RuleEvidence $evidence = null)
    {
        $this->evidence = $evidence ?? RuleEvidence::bundled();
    }

    /**
     * The change, kept, and the `ANALYZE` after it.
     *
     * @param  array<string, string>  $context  the table, where the statement names one the caller
     *                                          could read. Without it `{{table}}` stays visible, a
     *                                          hole the reader fills.
     */
    public function payload(array $context, string $ruleId, DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: array_map(
                static fn (RemediationStep $step): RemediationStep => $step->filled($context),
                [
                    new RemediationStep(
                        order: 1,
                        kind: RemediationStepKind::MigrationStatement,
                        noteKey: self::LANG.'keep_the_change',
                    ),
                    new RemediationStep(
                        order: 2,
                        kind: RemediationStepKind::MigrationStatement,
                        noteKey: self::LANG.'analyze',
                        sqlTemplate: 'ANALYZE {{table}}',
                    ),
                ],
            ),
            strategy: RemediationStrategy::AnalyzeAfter,
            ruleId: $ruleId,
            downtimeClass: $downtimeClass,
            verification: self::LANG.'verification',
            references: array_map(
                static fn (RuleEvidenceEntry $entry): string => $entry->url,
                $this->evidence->for($ruleId),
            ),
        );
    }
}
