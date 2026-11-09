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
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\NoSafeSequenceTemplate;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Subjects\DownLegDigest;
use Pushery\SQLens\Subjects\FoundSubjects;
use Pushery\SQLens\Subjects\MigrationStatementDigest;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A `down()` that drops a table or a column its `up()` only built where it was missing.
 *
 * ```php
 * public function up(): void
 * {
 *     if (! Schema::hasTable('ledger_markers')) {
 *         Schema::create('ledger_markers', fn (Blueprint $table) => ...);
 *     }
 * }
 *
 * public function down(): void
 * {
 *     Schema::dropIfExists('ledger_markers');
 * }
 * ```
 *
 * The guard is how a migration is written to run twice safely, and on an empty database the pair is
 * symmetric. On a database where an earlier install already holds `ledger_markers`, `up()` builds
 * nothing, and the rollback deletes the table with every row in it: data this migration never wrote.
 *
 * ## Why {@see DownMoreDestructiveRule} cannot see it
 *
 * Under pretend the guard is answered with nothing, so the `CREATE` is captured as if it always ran,
 * and a rollback that drops what `up()` created is the ordinary, symmetric one. The difference is in
 * the file only. The pre-scan reads it there ({@see FoundSubjects}): the tables and columns `up()`
 * asks about in a guard, and whether `down()` can throw. This rule puts that beside the rollback leg.
 *
 * ## What it compares
 *
 * - **A table dropped or truncated** is reported when `up()` asks whether it exists and creates it.
 *   A table `up()` asks about but never creates is {@see DownMoreDestructiveRule}'s finding.
 * - **A column dropped** is reported when `up()` asks whether it exists. Whether `up()` adds it is not
 *   asked of the statements, because on PostgreSQL an added column is not classified as one.
 *
 * A `down()` that can throw is left alone: a rollback that refuses while the data is there is the
 * remedy, and the parse cannot tell a refusal from any other `throw`, so every one counts as one.
 *
 * ## What it leaves to others
 *
 * A rollback this run could not read is {@see DownMoreDestructiveRule}'s to report as undetermined, and
 * this rule says nothing about it rather than a second time. A migration whose methods the pre-scan
 * could not tell apart carries no {@see FoundSubjects}, and gets no finding from a comparison nobody
 * made.
 */
final class DownDropsWhatUpFoundRule extends AbstractLifecycleRule implements ProvidesRemediation
{
    /** The rollback statements that take a whole table, rows and all. */
    private const array TABLE_DESTROYING = [
        StatementKind::DropTable,
        StatementKind::TruncateTable,
    ];

    /** The considered `none`: what down() may take depends on data the migration cannot see. */
    private readonly NoSafeSequenceTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new NoSafeSequenceTemplate;
    }

    public function id(): string
    {
        return 'GEN.L1.DOWN_DROPS_WHAT_UP_FOUND';
    }

    /**
     * A considered `none`. Each obvious template is wrong in one direction: taking the guard out of
     * `up()` makes it fail where the table already exists, and keeping `down()` as it is deletes rows
     * the migration never wrote. The remedy is a `down()` that refuses while there is data, and what
     * counts as data is the project's to say, so the note describes it rather than writing it.
     *
     * Offered only with a finding, so a statement the rule says nothing about carries no payload.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if (! $this->verdict($statement) instanceof RuleVerdict) {
            return null;
        }

        return $this->template->payload(
            'sqlens::messages.remediation.no_safe_sequence.down_drops_what_up_found',
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
     * Heuristic, for one reason: any `throw` in `down()` counts as a refusal, and a `throw` that
     * guards something else leaves a real finding unreported. What the rule does report is read off
     * the parse and the classified rollback, and is not estimated.
     */
    #[Override]
    public function confidence(): Confidence
    {
        return Confidence::Heuristic;
    }

    /** Preview, as every new check starts: it runs where a project asks for it. */
    #[Override]
    public function stability(): StabilityTier
    {
        return StabilityTier::Preview;
    }

    /** Online: applying the migration never runs `down()`, as {@see DownMoreDestructiveRule} explains. */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    #[Override]
    protected function verdict(MigrationStatementView $statement): ?RuleVerdict
    {
        // Once per migration: the fact is about its two halves, not about one statement.
        if (! $this->isFirstStatement($statement)) {
            return null;
        }

        $found = $statement->migration->foundSubjects;
        $leg = $statement->migration->downLeg;

        if (! $found instanceof FoundSubjects || ! $leg instanceof DownLegDigest || $found->downCanRefuse) {
            return null;
        }

        $lost = $this->lost($leg, $found, $statement);

        return $lost === [] ? null : RuleVerdict::flag($this->message($lost));
    }

    /**
     * What the rollback drops of the tables and columns `up()` asked about, in capture order.
     *
     * @return list<string> each a phrase naming one of them
     */
    private function lost(DownLegDigest $leg, FoundSubjects $found, MigrationStatementView $statement): array
    {
        $lost = [];
        $rollbacks = array_merge(...array_map(static fn (MigrationStatementDigest $digest): array => $digest->andItsActions(), $leg->statements));

        foreach ($rollbacks as $rollback) {
            if (in_array($rollback->kind, self::TABLE_DESTROYING, true)) {
                foreach ($rollback->targets as $target) {
                    if ($target->type === SchemaObjectType::Table
                        && in_array($this->comparable($target), $found->asked, true)
                        && $statement->migration->createsTable($target->qualifiedName())) {
                        $lost[] = sprintf('the table %s', $target->qualifiedName());
                    }
                }

                continue;
            }

            $table = $rollback->soleTarget(SchemaObjectType::Table);
            $column = $rollback->soleTarget(SchemaObjectType::Column);

            if ($rollback->kind === StatementKind::DropColumn
                && $table instanceof StatementTarget
                && $column instanceof StatementTarget
                && in_array($this->comparable($table).'.'.$this->comparable($column), $found->asked, true)) {
                $lost[] = sprintf('the column %s of %s', $column->qualifiedName(), $table->qualifiedName());
            }
        }

        return array_values(array_unique($lost));
    }

    /**
     * A target's name as the pre-scan writes a name it read: without quotes, in lower case.
     *
     * The canonical form quotes a name that would not survive unquoted, and the pre-scan reads the
     * literal the migration wrote, which carries no quotes. Folding the case as well makes `Orders`
     * and `orders` one name, which on PostgreSQL they are not; a migration that keeps both is rare
     * enough that a finding about the wrong one of them costs less than missing both.
     */
    private function comparable(StatementTarget $target): string
    {
        return strtolower(str_replace(['"', '`'], '', $target->qualifiedName()));
    }

    /** @param  non-empty-list<string>  $lost */
    private function message(array $lost): string
    {
        $last = array_pop($lost);
        $named = $lost === [] ? $last : implode('; ', $lost).'; and '.$last;

        return sprintf(
            'This migration\'s down() drops what its up() may have found already: %s. up() builds '
            .'each of them only where it is missing, so on a database where an earlier install '
            .'created it, up() built nothing, and this rollback deletes rows the migration never '
            .'wrote. Make down() refuse while they hold data, by throwing with the reason, or have it '
            .'remove only what up() built. Where nothing can be lost, such as a column derived from '
            .'the others, say so on the migration with #[SqlensIgnore] naming this rule and that reason.',
            $named,
        );
    }
}
