<?php

declare(strict_types=1);

namespace Pushery\SQLens\Remediation;

use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Rules\RuleEvidence;
use Pushery\SQLens\Rules\RuleEvidenceEntry;

/**
 * The staged drop — the contract half of expand/contract, for a removal that never had an expand.
 *
 * ## It does not make the drop harmless; it makes the ORDER explicit
 *
 * The statement at the end of this sequence is byte-identical to the one that was flagged. Nothing
 * here is a safer `DROP`, because there is no such thing: the object is gone either way. What
 * changes is what has already happened by the time it runs — a release that stopped using the
 * object, and a window long enough to be sure nothing still does.
 *
 * That is why three of the four steps are gates rather than statements. A reader looking for the
 * fix will find one line of SQL at position three and a lot of waiting in front of it, and the
 * waiting IS the fix.
 *
 * ## The observation window is a step, not a footnote
 *
 * "Ship the code that stops using it" and "wait until nothing uses it" are different claims, and
 * the second is the one that fails: a queue worker on the old release, a scheduler that has not
 * restarted, a cached container image. Folding the window into the deploy step would let a reader
 * do the first and believe they had done both.
 *
 * ## Why it names the destructive opt-in without offering it as an exit
 *
 * The rules this serves carry a `#[SqlensAllowDestructive]` opt-in, and a fix template is exactly
 * where somebody would look for permission to make the finding go away. It does not do that, and
 * the difference is worth stating precisely: the opt-in does NOT silence the rule. The finding is
 * still produced, and the attribute becomes a NAMED, VISIBLE suppression in the report, with its
 * reason shown. Recording the review is what it is for. A template that presented it as a way past
 * the gate would be a fix template teaching people to disable the check that found the problem.
 *
 * ## Driver-neutral
 *
 * `DROP TABLE` and `ALTER TABLE … DROP COLUMN` are the same statement on PostgreSQL and MySQL, so
 * this imports no driver and an architecture test holds the whole neutral namespace to that.
 *
 * ## It renders; it never runs
 *
 * Nothing here drops anything, and a sequence spanning two releases is not something a tool could
 * apply in any case. The gates in the middle are human decisions, and a tool that skipped them
 * would produce exactly the outage the sequence exists to prevent.
 */
final readonly class DeployWindowDropTemplate
{
    /** The key prefix every note, precondition and verification string of this template lives under. */
    private const string LANG = 'sqlens::messages.remediation.deploy_window_drop.';

    /** The shipped evidence register — a rule class must not name it, so the lookup lives here. */
    private RuleEvidence $evidence;

    public function __construct(?RuleEvidence $evidence = null)
    {
        $this->evidence = $evidence ?? RuleEvidence::bundled();
    }

    /**
     * The staged sequence for dropping a COLUMN.
     *
     * @param  array<string, string>  $context  placeholder values the caller measured
     */
    public function forColumn(array $context, string $ruleId, ?DowntimeClass $downtimeClass): RemediationPayload
    {
        return $this->payload('ALTER TABLE {{table}} DROP COLUMN {{column}}', $context, $ruleId, $downtimeClass);
    }

    /**
     * The staged sequence for dropping a TABLE — the same order, a shorter statement.
     *
     * Not folded into one method with a flag: the two produce different SQL, and a template that
     * chose between them from a boolean would put the decision at the call site, where a caller
     * that got it wrong would emit a `DROP COLUMN` with no column in it.
     *
     * @param  array<string, string>  $context  placeholder values the caller measured
     */
    public function forTable(array $context, string $ruleId, ?DowntimeClass $downtimeClass): RemediationPayload
    {
        return $this->payload('DROP TABLE {{table}}', $context, $ruleId, $downtimeClass);
    }

    /**
     * The class is NULLABLE, and that is a statement about the sequence rather than a concession.
     *
     * A staged drop is the same three steps whether or not the deploy-time cost of the final
     * statement is known: stop reading it, wait out the window, then drop. {@see RemediationPayload}
     * has always stored the class nullable for that reason, and it renders `downtime_class: null`
     * rather than omitting the field — an honest "not established" instead of a guess.
     *
     * The case that made it matter: MySQL's `drop_column` matrix entry is CONDITIONAL, so a run
     * that decided nothing about the live table resolves it to undetermined. Requiring a class here
     * would have meant a rule with a real fix to offer could not offer it, purely because the
     * unrelated cost question had no answer yet.
     *
     * @param  array<string, string>  $context
     */
    private function payload(string $dropStatement, array $context, string $ruleId, ?DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: array_map(
                static fn (RemediationStep $step): RemediationStep => $step->filled($context),
                [
                    // 1 — the release that stops using the object. Nothing about the schema changes.
                    new RemediationStep(
                        order: 1,
                        kind: RemediationStepKind::ManualGate,
                        noteKey: self::LANG.'release_without_it',
                    ),
                    // 2 — the window. A separate step because "shipped it" and "nothing uses it any
                    // more" are different claims, and the second is the one that fails.
                    new RemediationStep(
                        order: 2,
                        kind: RemediationStepKind::ManualGate,
                        noteKey: self::LANG.'observation_window',
                    ),
                    // 3 — the same statement that was flagged, in a later release.
                    new RemediationStep(
                        order: 3,
                        kind: RemediationStepKind::SeparateMigration,
                        noteKey: self::LANG.'drop_in_a_later_release',
                        sqlTemplate: $dropStatement,
                    ),
                    // 4 — record the review. NOT a way past the gate: the finding survives the
                    // attribute and becomes a named, visible suppression rather than disappearing.
                    new RemediationStep(
                        order: 4,
                        kind: RemediationStepKind::ManualGate,
                        noteKey: self::LANG.'record_the_review',
                        laravelSnippet: '#[SqlensAllowDestructive(reason: "…")]',
                    ),
                ],
            ),
            strategy: RemediationStrategy::DeployWindowDrop,
            ruleId: $ruleId,
            downtimeClass: $downtimeClass,
            preconditions: [
                self::LANG.'precondition.data_is_expendable',
                self::LANG.'precondition.release_boundary_available',
            ],
            verification: self::LANG.'verification',
            references: array_map(
                static fn (RuleEvidenceEntry $entry): string => $entry->url,
                $this->evidence->for($ruleId),
            ),
        );
    }
}
