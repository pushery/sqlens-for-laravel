<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Remediation\RemediationStep;
use Pushery\SQLens\Remediation\RemediationStepKind;
use Pushery\SQLens\Remediation\RemediationStrategy;

/**
 * What to do about a difference — as structured material, never as an applied change.
 *
 * ## Why a hint at all
 *
 * "The database and the migrations disagree about `public.orders`" is a true sentence that leaves
 * its reader exactly where they started. The comparison already knows which of three things
 * happened and which attributes moved; a report that keeps that to itself makes every reader
 * re-derive it by hand, and most of them will do it wrong once.
 *
 * ## It never picks a side, and that is the design rather than caution
 *
 * An object in the database that no migration describes has TWO honest remedies — write the
 * migration that creates it, or drop it — and which one is right depends on why it is there, which
 * this package cannot know. A hint that recommended one would be wrong half the time, and wrong in
 * the direction of deleting something on the half where it is wrong.
 *
 * So both routes are named, every time, and a test holds that. The decision stays with a person.
 *
 * ## No auto-fix, and the downtime class is why it matters here
 *
 * SQLens writes no migration file and executes no DDL — a declared non-goal. But the sharper reason
 * lives in this class specifically: **a correction is itself a migration.** An `ALTER` that puts a
 * column's type back can rewrite the whole table under a lock, so a hint applied blindly is exactly
 * the outage this package exists to prevent. Every payload therefore carries a
 * {@see DowntimeClass}, and the divergent one carries the loudest of the three.
 */
final readonly class DriftCorrectionHint
{
    private const string LANG = 'sqlens::messages.remediation.drift.';

    /**
     * The correction material for one difference.
     *
     * The SQL templates are deliberately templates rather than statements: the placeholder is what
     * says "a person fills this in". Emitting a runnable `DROP TABLE public.orders;` would be a
     * command somebody can paste in one motion, which is the shape this package refuses to hand out
     * for a decision it did not make.
     */
    public static function for(DriftEntry $entry): RemediationPayload
    {
        return match ($entry->class) {
            DriftClass::UnexpectedInDatabase => self::unexpected(),
            DriftClass::MissingInDatabase => self::missing(),
            DriftClass::Divergent => self::divergent(),
        };
    }

    /**
     * Live in the database, described by no migration — two routes, and the hint names both.
     *
     * `online` as the class: the object exists and stays, whichever route is taken next. The route
     * that DROPS it is a destructive migration with its own class, and the step that proposes it
     * says so rather than inheriting a reassuring one from here.
     */
    private static function unexpected(): RemediationPayload
    {
        return new RemediationPayload(
            steps: [
                new RemediationStep(
                    order: 1,
                    kind: RemediationStepKind::ManualGate,
                    noteKey: self::LANG.'unexpected.decide_first',
                ),
                new RemediationStep(
                    order: 2,
                    kind: RemediationStepKind::SeparateMigration,
                    noteKey: self::LANG.'unexpected.adopt_it',
                    laravelSnippet: "// keep it: write the migration that creates it, so a rebuilt\n"
                        ."// environment has it too\nSchema::create('{{object}}', function (Blueprint \$table): void {\n    // …\n});",
                ),
                new RemediationStep(
                    order: 3,
                    kind: RemediationStepKind::SeparateMigration,
                    noteKey: self::LANG.'unexpected.retire_it',
                    laravelSnippet: "// remove it: a destructive migration of its own, run in a window\n"
                        ."// you chose — sqlens:lint will class it for you\nSchema::drop('{{object}}');",
                ),
            ],
            strategy: RemediationStrategy::DriftCorrection,
            ruleId: DriftClass::UnexpectedInDatabase->ruleId(),
            downtimeClass: DowntimeClass::Online,
            preconditions: [self::LANG.'unexpected.precondition.know_why_it_is_there'],
            verification: self::LANG.'verification',
        );
    }

    /**
     * The migrations produce it and the database does not have it.
     *
     * The first step is a READ, not a write, and it is first because the two causes need opposite
     * answers: a migration that never ran is fixed by running it, and one that ran and did not do
     * what it claims needs a NEW migration — editing the old one would make every other environment
     * silently disagree with the file that describes it.
     */
    private static function missing(): RemediationPayload
    {
        return new RemediationPayload(
            steps: [
                new RemediationStep(
                    order: 1,
                    kind: RemediationStepKind::ManualGate,
                    noteKey: self::LANG.'missing.read_the_migration_table',
                    sqlTemplate: 'SELECT migration, batch FROM migrations ORDER BY id DESC LIMIT 20',
                ),
                new RemediationStep(
                    order: 2,
                    kind: RemediationStepKind::SeparateMigration,
                    noteKey: self::LANG.'missing.never_edit_an_applied_migration',
                ),
            ],
            strategy: RemediationStrategy::DriftCorrection,
            ruleId: DriftClass::MissingInDatabase->ruleId(),
            downtimeClass: DowntimeClass::Online,
            preconditions: [self::LANG.'missing.precondition.two_causes_one_absence'],
            verification: self::LANG.'verification',
        );
    }

    /**
     * Present on both sides, described differently — the class where the correction itself bites.
     *
     * `rewrite` rather than `online`, and it is the loudest of the three deliberately. Putting a
     * column's type or collation back is an `ALTER` that can rebuild the table under a lock: the
     * finding is `online` because reporting changes nothing, and the CORRECTION is not. A payload
     * that inherited the finding's class would tell a deploy script this is free.
     *
     * ## No `references`, and that is a correction rather than an omission
     *
     * The three builders below take no `DriftEntry` any more, and that is the same change seen from
     * the other side: the entry was passed in only to be put into `references`, so removing the
     * misuse left every one of them with a parameter nothing read.
     *
     * All three payloads here carried the drifted object's name in `references` — the divergent one
     * also carried its changed attributes. The published schema declares that field as a list of
     * URIs, so a consumer following the contract would have rendered `public.orders.note` as a link
     * to nowhere. It is a real breach of the attachment point, found by validating the payload
     * against the shipped `.json` rather than against this package's own idea of it.
     *
     * Nothing was lost by removing it. The finding's message already names the object and every
     * changed attribute WITH both sides — strictly more than the list held — and its Location names
     * the object again in a field meant for it. A drift correction cites no external document, so
     * the honest value for `references` is absent.
     */
    private static function divergent(): RemediationPayload
    {
        return new RemediationPayload(
            steps: [
                new RemediationStep(
                    order: 1,
                    kind: RemediationStepKind::ManualGate,
                    noteKey: self::LANG.'divergent.decide_which_side_is_right',
                ),
                new RemediationStep(
                    order: 2,
                    kind: RemediationStepKind::SeparateMigration,
                    noteKey: self::LANG.'divergent.alter_one_attribute_at_a_time',
                    sqlTemplate: 'ALTER TABLE {{table}} ALTER COLUMN {{column}} {{change}}',
                ),
                new RemediationStep(
                    order: 3,
                    kind: RemediationStepKind::ManualGate,
                    noteKey: self::LANG.'divergent.lint_the_correction',
                ),
            ],
            strategy: RemediationStrategy::DriftCorrection,
            ruleId: DriftClass::Divergent->ruleId(),
            // The loudest of the three, and the only honest one: an ALTER that puts a type back
            // rewrites the table. Saying `online` here would price a rebuild as free.
            downtimeClass: DowntimeClass::Rewrite,
            preconditions: [self::LANG.'divergent.precondition.the_alter_is_itself_a_migration'],
            verification: self::LANG.'verification',
        );
    }
}
