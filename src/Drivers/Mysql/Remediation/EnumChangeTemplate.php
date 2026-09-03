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
 * Changing a MySQL `ENUM` member list — where the first step is not a statement but a COMPARISON.
 *
 * ## Why the sequence opens by looking at the live column
 *
 * MySQL's `MODIFY` names the column's WHOLE definition, so the statement carries the list it will
 * END with and never the change. Six different operations produce statements that look alike:
 * appending, appending across the 255-member boundary, inserting in the middle, removing,
 * reordering, and renaming. Only a comparison with the live column says which one this is — so the
 * sequence cannot begin with SQL, and a template that pretended otherwise would be answering a
 * question nobody had asked yet.
 *
 * ## The row nobody expects
 *
 * Measured on a real 8.4: a RENAME of a member runs `INSTANT`. It is the cheapest change MySQL
 * offers here and one of the most dangerous — the stored values are ordinals, so renaming `'b'` to
 * `'B'` rewrites nothing, takes no lock, and every row that read `'b'` a moment ago now reads `'B'`
 * in an application that has not been redeployed.
 *
 * That is why cost and compatibility stay apart in this sequence: the cheap operation is the unsafe
 * one, and a template ordered by cost would recommend exactly it.
 *
 * ## No ALGORITHM, and that is the matrix talking
 *
 * The online-DDL matrix keys this operation CONDITIONALLY — on the member being appended at the end
 * and on the storage size being unchanged — and a static reader can decide neither, so the matrix
 * answers `undetermined` and the finding carries no downtime class. Naming an `ALGORITHM` here
 * would be inventing the answer the matrix declined to give, and it would be wrong for most of the
 * six cases.
 *
 * ## It renders; it never runs
 */
final readonly class EnumChangeTemplate
{
    /** The key prefix every note, precondition and verification string of this template lives under. */
    private const string LANG = 'sqlens::messages.remediation.mysql_enum.';

    /** The shipped evidence register — a rule class must not name it, so the lookup lives here. */
    private RuleEvidence $evidence;

    public function __construct(?RuleEvidence $evidence = null)
    {
        $this->evidence = $evidence ?? RuleEvidence::bundled();
    }

    /**
     * The sequence for an enumerated column's member list.
     *
     * @param  array<string, string>  $context  the table and the column, when the statement named them
     */
    public function forMemberListChange(array $context, string $ruleId, ?DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: array_map(
                static fn (RemediationStep $step): RemediationStep => $step->filled($context),
                [
                    // 1 — the comparison. Not SQL, because the question is which of six operations
                    // this statement performs, and the statement does not say.
                    new RemediationStep(
                        order: 1,
                        kind: RemediationStepKind::ManualGate,
                        noteKey: self::LANG.'compare_with_the_live_column',
                    ),
                    // 2 — the cheap case, and the only one that is also safe.
                    new RemediationStep(
                        order: 2,
                        kind: RemediationStepKind::MigrationStatement,
                        noteKey: self::LANG.'append_at_the_end',
                    ),
                    // 3 — everything else, by reference: a staged column swap, which already has a
                    // template. Restating it here would be a second definition of a four-phase plan.
                    new RemediationStep(
                        order: 3,
                        kind: RemediationStepKind::ManualGate,
                        noteKey: self::LANG.'anything_else_is_staged',
                    ),
                ],
            ),
            strategy: RemediationStrategy::EnumAppendOnly,
            ruleId: $ruleId,
            // Passed through rather than chosen: the matrix declines this operation, and a class
            // invented here would contradict the finding standing beside it.
            downtimeClass: $downtimeClass,
            preconditions: [
                self::LANG.'precondition.you_know_which_change_this_is',
                self::LANG.'precondition.rename_is_not_free',
            ],
            verification: self::LANG.'verification',
            references: array_map(
                static fn (RuleEvidenceEntry $entry): string => $entry->url,
                $this->evidence->for($ruleId),
            ),
        );
    }
}
