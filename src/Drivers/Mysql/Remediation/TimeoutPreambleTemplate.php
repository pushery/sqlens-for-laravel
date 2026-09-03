<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Remediation;

use Pushery\SQLens\Drivers\Mysql\Rules\L3\Support\MysqlTimeouts;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Remediation\RemediationStep;
use Pushery\SQLens\Remediation\RemediationStepKind;
use Pushery\SQLens\Remediation\RemediationStrategy;
use Pushery\SQLens\Rules\RuleEvidence;
use Pushery\SQLens\Rules\RuleEvidenceEntry;

/**
 * The fix material for a MySQL migration that never bounded its metadata-lock wait.
 *
 * ## Why this is not the PostgreSQL template with a different variable name
 *
 * Three differences, and each one would be a wrong instruction if carried across:
 *
 * - **There is no `SET LOCAL`.** PostgreSQL's `SET LOCAL` scopes a value to the migration's own
 *   transaction so it cannot leak into whatever the connection does next. MySQL has no such form,
 *   so the preamble is `SET SESSION` and the value stays for the rest of the connection. That is a
 *   real consequence and the note says so rather than pretending the two are equivalent.
 * - **There is only ONE line to write.** The PostgreSQL preamble has two, because that engine bounds
 *   the wait and the run separately. MySQL has no DDL counterpart to a statement timeout, so a
 *   second line would have to invent one — and the setting that looks like it, `max_execution_time`,
 *   demonstrably does not reach a non-SELECT.
 * - **The unit is SECONDS, plain.** PostgreSQL takes an interval string (`'3s'`); MySQL takes a bare
 *   number of seconds. A quoted value carried over would be a type error at the worst moment.
 *
 * ## The value stays a placeholder
 *
 * The same determinism rule as everywhere else, and here it has a second reason: a right
 * `lock_wait_timeout` depends on how long the busiest transaction on that table runs and on how much
 * deploy window there is. Neither is in the migration, so a number printed here would be a guess
 * wearing the costume of a recommendation.
 */
final readonly class TimeoutPreambleTemplate
{
    /** The key prefix every note, precondition and verification string of this template lives under. */
    private const string LANG = 'sqlens::messages.remediation.mysql_timeout_preamble.';

    private RuleEvidence $evidence;

    public function __construct(?RuleEvidence $evidence = null)
    {
        $this->evidence = $evidence ?? RuleEvidence::bundled();
    }

    /** The payload for a migration that takes a metadata lock without bounding the wait for it. */
    public function forLockWaitTimeout(string $ruleId, DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: [
                new RemediationStep(
                    order: 1,
                    kind: RemediationStepKind::SessionSetting,
                    noteKey: self::LANG.MysqlTimeouts::LOCK_WAIT_TIMEOUT,
                    // A bare number of seconds, unquoted, and a placeholder rather than a value.
                    sqlTemplate: sprintf('SET SESSION %s = {{%s}}', MysqlTimeouts::LOCK_WAIT_TIMEOUT, MysqlTimeouts::LOCK_WAIT_TIMEOUT),
                ),
                new RemediationStep(
                    order: 2,
                    kind: RemediationStepKind::ManualGate,
                    noteKey: self::LANG.'retry_rather_than_raise',
                ),
            ],
            strategy: RemediationStrategy::TimeoutPreamble,
            ruleId: $ruleId,
            downtimeClass: $downtimeClass,
            preconditions: [
                self::LANG.'precondition.deploy_can_retry',
                self::LANG.'precondition.session_scope_is_understood',
            ],
            verification: self::LANG.'verification',
            references: array_map(
                static fn (RuleEvidenceEntry $entry): string => $entry->url,
                $this->evidence->for($ruleId),
            ),
        );
    }
}
