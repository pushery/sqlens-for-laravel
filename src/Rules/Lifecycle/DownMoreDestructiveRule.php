<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Lifecycle;

use Override;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Findings\Confidence;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\NoSafeSequenceTemplate;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Subjects\DownLegDigest;
use Pushery\SQLens\Subjects\MigrationStatementDigest;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A `down()` that destroys more than its `up()` ever built — the rollback that takes data with
 * it that the migration never touched.
 *
 * The shape, in one migration:
 *
 * ```php
 * public function up(): void   { Schema::table('orders', fn ($t) => $t->string('status')); }
 * public function down(): void { Schema::dropIfExists('orders'); }
 * ```
 *
 * `up()` added a column; `down()` drops the whole table. Both halves read fine on their own, and
 * the file passes every test the project has — because nothing runs `down()` until the day a
 * deploy is already going wrong. Then the rollback that was supposed to be the way out deletes
 * every order in the system.
 *
 * ## Why this is a level-1 rule and its sibling is level 4
 *
 * {@see DownMissingRule} is about a rollback path that does not exist: nothing is destroyed, the
 * way back is simply absent, and that is the deploy-window question level 4 asks. This one IS
 * destruction — a `DROP TABLE` nobody asked for, sitting in a method that will be run under
 * pressure. It belongs in the destructive band with the other rules that flag data loss, and it
 * fires as early as level 1 because that is the level a project turns on when it wants to be
 * told before something is deleted.
 *
 * ## What it compares, and why the granularity differs by object
 *
 * A rollback statement is unaccounted for when the migration's `up()` gives no reason for it:
 *
 * - **A table dropped or truncated** is unaccounted unless `up()` CREATED that table. Dropping a
 *   table you just created is the single most ordinary rollback there is; dropping one you only
 *   added a column to is the incident above.
 * - **A column, index or constraint dropped** is unaccounted when `up()` never touched that table
 *   at all. The bar is deliberately lower here — "up() touched this table" rather than "up()
 *   created this exact object" — and it is a false-NEGATIVE trade made on purpose. Laravel's
 *   `$table->dropColumn(['a', 'b'])` emits ONE statement with two clauses, of which the
 *   classification names the first; and on PostgreSQL an added column is not classified as an
 *   add-column at all, so "up() added exactly this column" is not a question that can be asked
 *   the same way on both engines. Asking it anyway would flag the commonest symmetric migration
 *   in existence on one engine and not the other. What the rule loses by asking the coarser
 *   question is a `down()` that drops a DIFFERENT column of a table `up()` did touch; what it
 *   would lose by asking the finer one is its users.
 *
 * A rollback that only DROPs things `up()` created — the symmetric one everybody writes — says
 * nothing at all.
 *
 * ## Why the same mechanism serves both engines
 *
 * Everything above is read from the canonical statement stream and its classified targets, which
 * both drivers produce through the same pipeline. There is nothing engine-specific in the
 * comparison, so there is one implementation and no MySQL twin — the engine difference that does
 * exist (MySQL's implicit commit makes a half-run rollback un-undoable) is a SENTENCE, and it
 * lives in the driver-notes register rather than in a second rule.
 *
 * ## Why the finding carries `online`
 *
 * The downtime class answers what APPLYING this migration costs, and applying it never runs
 * `down()`. A class derived from the rollback's own `DROP TABLE` would tell a deploy script that
 * a migration blocks when it does not — the exact decision the field exists to get right. The
 * rollback's cost is real and belongs in the prose, not on the deploy axis.
 */
final class DownMoreDestructiveRule extends AbstractLifecycleRule implements ProvidesRemediation
{
    /**
     * The rollback statements that destroy a whole TABLE.
     *
     * `TRUNCATE` sits beside `DROP` because the two differ in what is left standing, not in what
     * is lost: an empty table and no table are the same answer to the user whose rows are gone.
     */
    private const array TABLE_DESTROYING = [
        StatementKind::DropTable,
        StatementKind::TruncateTable,
    ];

    /** The rollback statements that destroy something INSIDE a table. */
    private const array MEMBER_DESTROYING = [
        StatementKind::DropColumn,
        StatementKind::DropIndex,
        StatementKind::DropConstraint,
    ];

    /** The considered `none` — narrowing THIS rollback is a decision, not a sequence. */
    private readonly NoSafeSequenceTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new NoSafeSequenceTemplate;
    }

    public function id(): string
    {
        return 'GEN.L1.DOWN_MORE_DESTRUCTIVE';
    }

    /**
     * A considered `none` — and the place where handing over the OBVIOUS sequence would be the
     * mistake.
     *
     * The obvious one is the deploy-window drop: the rollback destroys a table, this package has a
     * staged-drop template, point at it. That would be advice to CARRY OUT the destruction, on the
     * reading that it was intended — and the far likelier reading is the one the class docblock
     * opens with: a `dropIfExists` that was copied from the migration next to it and drops a table
     * holding every order in the system. A payload cannot tell those apart, and only one of the two
     * mistakes is recoverable.
     *
     * So the reason names both branches and hands over neither plan. If the rollback is asymmetric
     * by accident, narrow it to the inverse of `up()`. If the removal was genuinely intended, it
     * does not belong in a `down()` at all — it belongs in an `up()` of its own, where the
     * deploy-window sequence applies and where somebody decides to run it.
     *
     * Offered only for the FLAG. An undetermined verdict here means the rollback could not be read,
     * and a payload about destroying too much would be describing a method this run never saw.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        $verdict = $this->verdict($statement);

        if (! $verdict instanceof RuleVerdict || $verdict->isUndetermined() || $verdict->isPass) {
            return null;
        }

        return $this->template->payload(
            'sqlens::messages.remediation.no_safe_sequence.down_more_destructive',
            'sqlens::messages.remediation.no_safe_sequence.down_verification',
            $this->id(),
            $this->downtimeClass(),
        );
    }

    public function level(): Level
    {
        return Level::Destructive;
    }

    /**
     * Deterministic: which objects a rollback destroys and which ones the migration created are
     * both read off the classified statement streams. Nothing here is estimated — what the rule
     * cannot read, it reports as undetermined instead of guessing at.
     */
    #[Override]
    public function confidence(): Confidence
    {
        return Confidence::Deterministic;
    }

    /** Online — applying the migration never runs `down()`; see the class docblock. */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    #[Override]
    protected function verdict(MigrationStatementView $statement): ?RuleVerdict
    {
        // Once per migration: the fact is about the migration's two halves, not about the
        // statement that happens to carry the finding.
        if (! $this->isFirstStatement($statement)) {
            return null;
        }

        $leg = $statement->migration->downLeg;

        // Nothing looked. A subject built outside a capture carries no rollback leg, and reading
        // that absence as "the rollback destroys nothing" would be a verdict about a method the
        // run never read — the same blind spot `null` guards against on the down-method state.
        if (! $leg instanceof DownLegDigest) {
            return null;
        }

        $unreadable = $leg->unreadableReason;

        if ($unreadable instanceof UndeterminedReason) {
            return RuleVerdict::undetermined(
                'This migration\'s down() could not be read, so whether rolling back would destroy '
                .'more than up() built is unknown. It is not reported as safe: a rollback SQLens '
                .'could not parse is the one it must not vouch for.',
                $unreadable,
            );
        }

        $unaccounted = $this->unaccountedDestruction($leg, $statement);

        // An unclassified statement is reported on ONE side at a time, and which side depends on
        // what the comparison currently says. The asymmetry is not a compromise — it follows from
        // the direction each half of the comparison can move the verdict:
        //
        //   * knowing MORE about up() can only ADD reasons for a rollback statement to exist, so an
        //     unclassified up() statement can only turn a flag into a silence. It therefore matters
        //     exactly when there IS something to flag — and reporting it when there is not would put
        //     an undetermined on every migration whose up() opens with `SET lock_timeout`, which is
        //     the preamble this package's own lock rules ask for;
        //   * knowing MORE about down() can only ADD destructions, so an unclassified down()
        //     statement can only turn a silence into a flag. It therefore matters exactly when the
        //     comparison is about to say nothing — which is where a rollback SQLens could not read
        //     would otherwise be vouched for.
        if ($unaccounted !== []) {
            return $this->hasUnclassified($statement->migration->statements)
                ? RuleVerdict::undetermined(
                    'This migration\'s down() destroys things its up() gives no reason for — but one '
                    .'of up()\'s own statements was captured without being classified, so what the '
                    .'migration creates could not be enumerated in full. The rollback may well be '
                    .'symmetric after all; this run cannot say either way.',
                    UndeterminedReason::UpStateNotCapturable,
                )
                : RuleVerdict::flag($this->message($unaccounted));
        }

        return $this->hasUnclassified($leg->statements)
            ? RuleVerdict::undetermined(
                'What this migration\'s down() would destroy could not be determined — one of its '
                .'statements was captured but not classified. An unreadable rollback statement may '
                .'be the one that drops a table, so this is reported rather than passed over.',
                UndeterminedReason::DownStateNotCapturable,
            )
            : null;
    }

    /**
     * What the rollback destroys that `up()` gives no reason for, in capture order.
     *
     * @return list<string> each a human phrase naming one destruction
     */
    private function unaccountedDestruction(DownLegDigest $leg, MigrationStatementView $statement): array
    {
        $touched = $this->tablesTouchedByUp($statement);
        $unaccounted = [];

        foreach ($leg->statements as $rollback) {
            $table = $rollback->soleTarget(SchemaObjectType::Table);

            // A rollback statement naming no single table — or naming two, as a foreign key does —
            // is not one this comparison can place. It is not treated as a destruction, because a
            // finding has to be able to name what it is about.
            if (! $table instanceof StatementTarget) {
                continue;
            }

            $name = $table->qualifiedName();

            if (in_array($rollback->kind, self::TABLE_DESTROYING, true) && ! $statement->migration->createsTable($name)) {
                $unaccounted[] = $rollback->kind === StatementKind::DropTable
                    ? sprintf('it drops the table %s, which up() did not create', $name)
                    : sprintf('it truncates the table %s, which up() did not create', $name);

                continue;
            }

            if (in_array($rollback->kind, self::MEMBER_DESTROYING, true) && ! in_array($name, $touched, true)) {
                $unaccounted[] = sprintf(
                    'it drops %s from the table %s, which up() never touched',
                    $this->memberLabel($rollback),
                    $name,
                );
            }
        }

        return $unaccounted;
    }

    /**
     * The canonical names of every table `up()` names in any of its statements.
     *
     * Every target, not the sole one: an `ADD CONSTRAINT … REFERENCES` names two tables and both
     * are genuinely touched by the migration, so a rollback that drops something from either of
     * them has a reason to exist.
     *
     * @return list<string>
     */
    private function tablesTouchedByUp(MigrationStatementView $statement): array
    {
        $tables = [];

        foreach ($statement->migration->statements as $digest) {
            foreach ($digest->targets as $target) {
                if ($target->type === SchemaObjectType::Table) {
                    $tables[] = $target->qualifiedName();
                }
            }
        }

        return array_values(array_unique($tables));
    }

    /** What a member-destroying rollback statement destroys, named as precisely as it can be. */
    private function memberLabel(MigrationStatementDigest $rollback): string
    {
        $type = match ($rollback->kind) {
            StatementKind::DropColumn => SchemaObjectType::Column,
            StatementKind::DropIndex => SchemaObjectType::Index,
            default => SchemaObjectType::Constraint,
        };

        $target = $rollback->soleTarget($type);

        return $target instanceof StatementTarget
            ? sprintf('the %s %s', $type->value, $target->qualifiedName())
            : sprintf('a %s', $type->value);
    }

    /**
     * Whether any statement in the stream reached a rule without a usable classification.
     *
     * `Unknown` counts as unclassified on purpose: it is the classifier saying it did not
     * recognize the statement, which is the same knowledge state as no kind at all.
     *
     * @param  list<MigrationStatementDigest>  $statements
     */
    private function hasUnclassified(array $statements): bool
    {
        return array_any(
            $statements,
            static fn (MigrationStatementDigest $digest): bool => ! $digest->kind instanceof StatementKind || $digest->kind === StatementKind::Unknown,
        );
    }

    /** @param  non-empty-list<string>  $unaccounted */
    private function message(array $unaccounted): string
    {
        return sprintf(
            'This migration\'s down() destroys more than its up() built: %s. A rollback is run at the '
            .'worst possible moment — a deploy that is already going wrong — and this one would take '
            .'away data the migration never added, which no rollback can put back. Make down() the '
            .'exact inverse of up(): undo what up() did and nothing else. If part of this migration '
            .'genuinely cannot be undone, throw from down() with that reason rather than destroying '
            .'something adjacent to make the schema look right.',
            $this->joinPhrases($unaccounted),
        );
    }

    /**
     * The destructions as one English list.
     *
     * Semicolons rather than commas, because every phrase already CONTAINS a comma ("the table
     * orders, which up() did not create"). Separated by commas the list reads as twice as many
     * items as it has, and the reader has to parse it to find out how many things are being
     * destroyed — which is the one number the finding exists to convey.
     *
     * @param  non-empty-list<string>  $phrases
     */
    private function joinPhrases(array $phrases): string
    {
        if (count($phrases) === 1) {
            return $phrases[0];
        }

        $last = array_pop($phrases);

        return implode('; ', $phrases).'; and '.$last;
    }
}
