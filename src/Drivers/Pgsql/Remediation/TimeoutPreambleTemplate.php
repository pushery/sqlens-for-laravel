<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Remediation;

use Pushery\SQLens\Drivers\Pgsql\Rules\L3\Support\ExpectedTimeouts;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Remediation\RemediationStep;
use Pushery\SQLens\Remediation\RemediationStepKind;
use Pushery\SQLens\Remediation\RemediationStrategy;
use Pushery\SQLens\Rules\RuleEvidence;
use Pushery\SQLens\Rules\RuleEvidenceEntry;

/**
 * The two-line preamble that stops a migration from waiting forever — and the retry rule without
 * which it only moves the failure somewhere else.
 *
 * ## What the preamble actually buys
 *
 * `lock_timeout` caps how long a statement waits IN THE LOCK QUEUE. That is the one that prevents
 * the pile-up: a DDL blocked behind one long-running query holds its place in the queue, and every
 * later query wanting that table queues behind IT. One `ALTER TABLE` can stall an application
 * without ever having run. `statement_timeout` caps how long a statement RUNS once it has the lock
 * — a different failure, on a different axis, which is why the two are separate rules and separate
 * payloads rather than one preamble emitted twice.
 *
 * ## Why the retry gate is not optional
 *
 * A `lock_timeout` does not make the migration succeed. It makes it FAIL FAST, which is only an
 * improvement if somebody has decided what happens next. Without that decision the timeout is a
 * broken deploy where there used to be a slow one, and the instinctive response — raise the value —
 * gives back exactly the unbounded wait the setting was added to remove. The answer is to retry the
 * deploy when the table is quieter, and it is a `manual_gate` because it is a decision rather than
 * a statement.
 *
 * ## Why the values stay placeholders
 *
 * There is no honest number here. A right `lock_timeout` depends on how long the busiest
 * transaction on that table runs and on how much of a deploy window there is, neither of which is
 * in the migration. SQLens sets timeouts on its OWN capture session, and those values are
 * deliberately not offered as a recommendation: what a read-only linter is willing to wait for says
 * nothing about what a deploy should.
 *
 * The project's `expected_timeouts` config says WHICH timeouts a migration must set; it holds no
 * values, which is why it can gate the rules and not fill this template.
 *
 * ## One payload per omission
 *
 * The rule that fires knows which timeout is missing, and the payload carries exactly that line. A
 * migration missing both gets two findings and two one-line preambles — never a payload telling
 * somebody to add a setting they already have.
 *
 * ## It renders; it never runs
 *
 * SQLens sets nothing on the user's session. The preamble is material for the migration to carry
 * itself, which is the whole distinction between the tool's own session defense and this advice.
 */
final readonly class TimeoutPreambleTemplate
{
    /** The key prefix every note, precondition and verification string of this template lives under. */
    private const string LANG = 'sqlens::messages.remediation.timeout_preamble.';

    /**
     * The shipped evidence register — a rule class must not name it, so the lookup lives here.
     */
    private RuleEvidence $evidence;

    public function __construct(?RuleEvidence $evidence = null)
    {
        $this->evidence = $evidence ?? RuleEvidence::bundled();
    }

    /**
     * The preamble for the ONE timeout this finding is about.
     *
     * @param  string  $timeout  a name from {@see ExpectedTimeouts::KNOWN} — the same vocabulary the
     *                           rules are gated on, so a payload can never recommend a GUC the
     *                           config surface does not know
     */
    public function forTimeout(string $timeout, string $ruleId, DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: [
                new RemediationStep(
                    order: 1,
                    kind: RemediationStepKind::SessionSetting,
                    noteKey: self::LANG.$timeout,
                    // The value stays a placeholder. `SET LOCAL` scopes it to the migration's own
                    // transaction, so it cannot leak into whatever the connection does afterwards —
                    // and a `CONCURRENTLY` migration, which has no transaction, uses the plain form.
                    sqlTemplate: sprintf("SET LOCAL %s = '{{%s}}'", $timeout, $timeout),
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
                self::LANG.'precondition.value_is_a_decision',
            ],
            verification: self::LANG.'verification',
            references: array_map(
                static fn (RuleEvidenceEntry $entry): string => $entry->url,
                $this->evidence->for($ruleId),
            ),
        );
    }
}
