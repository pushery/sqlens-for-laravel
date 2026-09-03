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
 * Appending a value to a PostgreSQL enum — the ONE enum change the engine performs cheaply, and the
 * only one this template describes.
 *
 * ## Why there is nothing here for removing a value
 *
 * PostgreSQL has no `ALTER TYPE … DROP VALUE`. Not "it is expensive" — it does not exist. Removing
 * a value means building a new type and moving the column onto it, which is a staged column swap
 * and already has a template. So the rules for a removal or a rename hand over THAT sequence
 * instead, and this file stays silent about them rather than inventing a shorter-looking path to
 * the same place.
 *
 * The same holds for Laravel's `$table->enum()`, which makes no enum type at all — it is a varchar
 * with a `CHECK (col IN (…))`, so changing its values is a constraint change and gets the
 * `NOT VALID` → `VALIDATE` sequence. Three different remedies, because they are three different
 * operations that only share a word.
 *
 * ## The two catches an append has, and the version trap in one of them
 *
 * The new value cannot be USED in the transaction it is added in — on PostgreSQL 12 and later. The
 * received wisdom is the older, blanket "`ADD VALUE` cannot run in a transaction at all", which
 * stopped being true in 12; repeating it on this baseline would be a version trap, and a wrong old
 * rule is worse than a missing one. So the sequence separates the ADDING from the USING and says
 * which of the two the transaction boundary is about.
 *
 * The second catch has no fix and is stated rather than solved: the step is irreversible. A `down()`
 * cannot remove an enum value, so the migration cannot be cleanly rolled back — which is a reason to
 * ask whether a lookup table would serve better, not a step to perform.
 *
 * ## It renders; it never runs
 */
final readonly class EnumChangeTemplate
{
    /** The key prefix every note, precondition and verification string of this template lives under. */
    private const string LANG = 'sqlens::messages.remediation.enum_append.';

    /** The shipped evidence register — a rule class must not name it, so the lookup lives here. */
    private RuleEvidence $evidence;

    public function __construct(?RuleEvidence $evidence = null)
    {
        $this->evidence = $evidence ?? RuleEvidence::bundled();
    }

    /**
     * The append sequence.
     *
     * @param  array<string, string>  $context  the type, and the value when the statement quoted one
     *                                          plainly enough to read
     */
    public function forAddValue(array $context, string $ruleId, DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: array_map(
                static fn (RemediationStep $step): RemediationStep => $step->filled($context),
                [
                    new RemediationStep(
                        order: 1,
                        kind: RemediationStepKind::SeparateMigration,
                        noteKey: self::LANG.'add_value',
                        sqlTemplate: "ALTER TYPE {{type}} ADD VALUE IF NOT EXISTS '{{value}}'",
                    ),
                    new RemediationStep(
                        order: 2,
                        kind: RemediationStepKind::ManualGate,
                        noteKey: self::LANG.'use_it_afterwards',
                    ),
                    new RemediationStep(
                        order: 3,
                        kind: RemediationStepKind::ManualGate,
                        noteKey: self::LANG.'irreversible',
                    ),
                ],
            ),
            strategy: RemediationStrategy::EnumAppendOnly,
            ruleId: $ruleId,
            downtimeClass: $downtimeClass,
            preconditions: [
                self::LANG.'precondition.append_is_all_you_need',
                self::LANG.'precondition.readers_tolerate_unknown_values',
            ],
            verification: self::LANG.'verification',
            references: array_map(
                static fn (RuleEvidenceEntry $entry): string => $entry->url,
                $this->evidence->for($ruleId),
            ),
        );
    }
}
