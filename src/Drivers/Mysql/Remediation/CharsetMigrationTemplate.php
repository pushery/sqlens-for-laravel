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
 * Moving a table to `utf8mb4` — where the conversion is the easy part and the index lengths are
 * what actually stops the deploy.
 *
 * ## Why the first step is a check rather than a statement
 *
 * `utf8mb3` reserves three bytes per character and `utf8mb4` reserves four, and InnoDB's index key
 * limit is counted in BYTES. A `varchar(255)` key that fit comfortably at 765 bytes becomes 1020;
 * a composite key that fit at 3000 becomes 4000 and the server refuses it outright. So the
 * commonest way this migration ends is not slowly — it is immediately, with an error, on a table
 * that is now half converted if the statement was one of several.
 *
 * That check gets its own step because it is the one people skip. Folded into a note under the
 * conversion, it reads as background; standing first, it reads as the thing to do before anything
 * else.
 *
 * ## No prefix length is offered
 *
 * What to do about a key that no longer fits — shorten the prefix, narrow the column, drop the
 * index — depends on what the index is FOR, and that is not in the statement. A number invented
 * here would be a schema decision made by a linter, which is the one thing it must never be.
 *
 * ## The step after the conversion is the one that makes it stick
 *
 * A converted column with a connection still speaking `utf8mb3` accepts the writes and stores the
 * replacement character, silently. The table is `utf8mb4`, the data is not, and nothing errors.
 * That is why the connection and server side is a named step rather than an afterthought.
 *
 * ## The clause values are not restated here
 *
 * `ALGORITHM` and `LOCK` belong to the matrix and to the template that reads it. This one points at
 * that recipe rather than writing values of its own, which would be a second decision table for the
 * same operation.
 *
 * ## It renders; it never runs
 *
 * A character-set conversion re-encodes every value in the table. Nothing about it is something a
 * tool should apply on somebody's behalf.
 */
final readonly class CharsetMigrationTemplate
{
    /** The key prefix every note, precondition and verification string of this template lives under. */
    private const string LANG = 'sqlens::messages.remediation.charset_migration.';

    /** The shipped evidence register — a rule class must not name it, so the lookup lives here. */
    private RuleEvidence $evidence;

    public function __construct(?RuleEvidence $evidence = null)
    {
        $this->evidence = $evidence ?? RuleEvidence::bundled();
    }

    /**
     * The staged conversion.
     *
     * @param  array<string, string>  $context  the table, when the statement named one. The target
     *                                          COLLATION stays a placeholder: `utf8mb4` has several
     *                                          and they sort differently, so picking one is a
     *                                          product decision rather than a fact in the SQL.
     */
    public function payload(array $context, string $ruleId, ?DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: array_map(
                static fn (RemediationStep $step): RemediationStep => $step->filled($context),
                [
                    new RemediationStep(
                        order: 1,
                        kind: RemediationStepKind::ManualGate,
                        noteKey: self::LANG.'check_index_lengths',
                    ),
                    new RemediationStep(
                        order: 2,
                        kind: RemediationStepKind::MigrationStatement,
                        noteKey: self::LANG.'convert',
                        sqlTemplate: 'ALTER TABLE {{table}} CONVERT TO CHARACTER SET utf8mb4 COLLATE {{collation}}',
                    ),
                    new RemediationStep(
                        order: 3,
                        kind: RemediationStepKind::ManualGate,
                        noteKey: self::LANG.'follow_the_connection',
                    ),
                    new RemediationStep(
                        order: 4,
                        kind: RemediationStepKind::ManualGate,
                        noteKey: self::LANG.'window_or_stage_it',
                    ),
                ],
            ),
            strategy: RemediationStrategy::CharsetMigration,
            ruleId: $ruleId,
            downtimeClass: $downtimeClass,
            preconditions: [
                self::LANG.'precondition.collation_is_a_decision',
                self::LANG.'precondition.size_is_an_estimate',
            ],
            verification: self::LANG.'verification',
            references: array_map(
                static fn (RuleEvidenceEntry $entry): string => $entry->url,
                $this->evidence->for($ruleId),
            ),
        );
    }
}
