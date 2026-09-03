<?php

declare(strict_types=1);

namespace Pushery\SQLens\Remediation;

use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Rules\RuleEvidence;
use Pushery\SQLens\Rules\RuleEvidenceEntry;

/**
 * The fix for an identifier that goes over the engine's limit: give the object a name of your own.
 *
 * ## Why this is the shortest template in the package, and why that is right
 *
 * Every other strategy here stages a change over time because the DATABASE needs the staging — a
 * window to drain readers, a backfill to batch, a constraint to validate separately. None of that
 * applies. Nothing about the schema moves, no row is read or written, and there is no state between
 * the steps that could be left half-applied. The remedy is an argument.
 *
 * So the template does not pad itself out to look like the others. A three-step sequence where one
 * step is the whole answer teaches a reader that the first two mattered.
 *
 * ## The second step is engine-specific, and that is the part worth having
 *
 * The two engines fail in opposite directions, so what a reader must check afterwards differs:
 *
 * - **PostgreSQL truncated and carried on.** If this migration has already run anywhere — a
 *   developer's machine, a review app, staging — that database now holds the object under the
 *   truncated name. Renaming the migration does not rename it there, and the next deploy will
 *   create a SECOND object under the new name beside the first. The step names that.
 * - **MySQL refused the statement.** Nothing was created, anywhere, so there is nothing to
 *   reconcile — and saying so is worth a step, because a reader who has just read the PostgreSQL
 *   advice would otherwise go looking for an object that does not exist.
 *
 * Two methods rather than one with a flag, for the reason {@see DeployWindowDropTemplate} gives:
 * they produce different material, and a caller that got the flag wrong would hand a reader the
 * other engine's reconciliation.
 */
final readonly class ExplicitIdentifierTemplate
{
    /** The key prefix every note, precondition and verification string of this template lives under. */
    private const string LANG = 'sqlens::messages.remediation.explicit_identifier.';

    /** The shipped evidence register — a rule class must not name it, so the lookup lives here. */
    private RuleEvidence $evidence;

    public function __construct(?RuleEvidence $evidence = null)
    {
        $this->evidence = $evidence ?? RuleEvidence::bundled();
    }

    /**
     * PostgreSQL: the object was created under a truncated name wherever this already ran.
     *
     * @param  array<string, string>  $context  placeholder values the caller measured
     */
    public function forPostgres(array $context, string $ruleId, ?DowntimeClass $downtimeClass): RemediationPayload
    {
        return $this->payload(self::LANG.'postgres_reconcile_the_truncated_object', $context, $ruleId, $downtimeClass);
    }

    /**
     * MySQL: the statement was refused, so nothing exists to reconcile.
     *
     * @param  array<string, string>  $context  placeholder values the caller measured
     */
    public function forMysql(array $context, string $ruleId, ?DowntimeClass $downtimeClass): RemediationPayload
    {
        return $this->payload(self::LANG.'mysql_nothing_was_created', $context, $ruleId, $downtimeClass);
    }

    /** @param  array<string, string>  $context */
    private function payload(string $reconcileKey, array $context, string $ruleId, ?DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: array_map(
                static fn (RemediationStep $step): RemediationStep => $step->filled($context),
                [
                    // 1 — the fix. Laravel derives a name only when none is given, so passing one
                    // takes the length out of the schema builder's hands entirely.
                    new RemediationStep(
                        order: 1,
                        kind: RemediationStepKind::MigrationStatement,
                        noteKey: self::LANG.'name_it_explicitly',
                        laravelSnippet: "\$table->index([…], 'a_name_you_chose');",
                    ),
                    // 2 — what to check afterwards, which is the half that differs by engine.
                    new RemediationStep(
                        order: 2,
                        kind: RemediationStepKind::ManualGate,
                        noteKey: $reconcileKey,
                    ),
                ],
            ),
            strategy: RemediationStrategy::ExplicitIdentifier,
            ruleId: $ruleId,
            downtimeClass: $downtimeClass,
            preconditions: [self::LANG.'precondition.the_name_is_free'],
            verification: self::LANG.'verification',
            references: array_map(
                static fn (RuleEvidenceEntry $entry): string => $entry->url,
                $this->evidence->for($ruleId),
            ),
        );
    }
}
