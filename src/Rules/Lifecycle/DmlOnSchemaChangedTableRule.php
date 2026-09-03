<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Lifecycle;

use Override;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Deploy\Contracts\DeclaresOperationClass;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\BatchedBackfillTemplate;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Subjects\MigrationContext;
use Pushery\SQLens\Subjects\MigrationStatementDigest;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A migration that CHANGES the schema of an existing table and WRITES that table's data
 * in the same transaction. Laravel wraps `up()` in one transaction by default, so the
 * schema change's exclusive lock on the table is held for the whole data write too — the
 * lock window is the sum of both, not the schema change alone — and the two cannot be
 * deployed, timed out, or rolled back independently. The safe shape is two steps: change
 * the schema in one migration, backfill the data in a separate migration (or a queued
 * job) that runs after the first has committed and released its lock.
 *
 * This is a lifecycle concern, not a PostgreSQL one — mixing a schema change and a data
 * write on the same table in one transaction is risky on every engine — so it lives in
 * the driver-neutral family and reasons only about the neutral classification: a `Dml`
 * statement whose target table is also the target of a schema-changing statement in the
 * same transaction. It is deliberately the companion the level-3 bundled-locks rule
 * (`PG.L3.RISKY_OPS_SINGLE_TX`) names and defers to.
 *
 * Two deliberate non-findings. A table the SAME migration created is invisible outside
 * the transaction until commit, so creating it and seeding it is not the contended case —
 * exactly the carve-out the blocking-DDL rules make. And `CreateTable` is not a
 * schema CHANGE of an existing table, so a create-then-insert pair never trips it. The
 * finding is deterministic — the mix is a fact of the statement stream — and reported
 * once, on the first data write that lands on a schema-changed table.
 */
final class DmlOnSchemaChangedTableRule extends AbstractLifecycleRule implements DeclaresOperationClass, ProvidesRemediation
{
    /**
     * The kinds that change an EXISTING table's structure and hold a lock on it while
     * they do. `CreateTable` is excluded on purpose (a fresh table nobody waits on);
     * `Dml` and `Unknown` are not schema changes.
     *
     * @var list<StatementKind>
     */
    private const array SCHEMA_CHANGE_KINDS = [
        StatementKind::AlterTable,
        // `ADD COLUMN`, and its absence here was a live defect rather than a precaution.
        //
        // MySQL's canonicalization has always classified `ALTER TABLE … ADD COLUMN` as its own kind,
        // so on MySQL this rule went silent on the pair it exists for — add a column, write to it in
        // the same transaction — while reporting the symmetric `DROP COLUMN` case beside it.
        // PostgreSQL only appeared covered because it fell back to `AlterTable`; the moment its
        // grammar names the statement, the same hole opens there. Measured, both engines.
        StatementKind::AddColumn,
        StatementKind::AddConstraint,
        StatementKind::DropConstraint,
        StatementKind::DropColumn,
        StatementKind::CreateIndex,
        StatementKind::DropIndex,
        StatementKind::Rename,
        StatementKind::DdlOther,
    ];

    /** The neutral batch recipe this rule points at, opened by the split it prescribes. */
    private readonly BatchedBackfillTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new BatchedBackfillTemplate;
    }

    public function id(): string
    {
        return 'GEN.L3.DML_ON_SCHEMA_CHANGED_TABLE';
    }

    /**
     * An unbatched backfill writes every row it touches inside ONE transaction, so its cost is rows and
     * its danger is a transaction that grows until it blocks vacuum or exhausts the undo log. The line
     * is the lowest of the four, because the failure mode arrives long before the runtime does.
     */
    public function operationClass(): string
    {
        return 'backfill';
    }

    /**
     * Split the write out of the schema change's transaction, then batch it.
     *
     * The order is the whole content of the plan. Batching a write that still shares the schema
     * change's transaction is not a smaller fix, it is a WORSE one: the exclusive lock is held until
     * commit, so every batch and every pause between batches happens under it. The split is what
     * makes the rest of the recipe help rather than hurt, which is why it is step one and why this
     * rule reaches for the batch template's split entry point rather than its plain one.
     *
     * The payload is offered for the UNDETERMINED verdict too, and that is deliberate. When the
     * transaction context could not be resolved, the rule's own text says "split them anyway" — the
     * advice does not depend on the answer, because a write in its own migration is correct either
     * way. Withholding the material there would leave the harder case with less help than the easy
     * one.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if (! $this->reportsOn($statement, unresolvedContext: false) && ! $this->reportsOn($statement, unresolvedContext: true)) {
            return null;
        }

        $table = $statement->soleTarget(SchemaObjectType::Table);

        // The table is filled only where the classification named exactly one. A write whose target
        // could not be pinned down keeps its placeholder standing rather than borrowing a name from
        // the migration's other statements.
        $context = $table instanceof StatementTarget ? ['table' => $table->qualifiedName()] : [];

        return $this->template->forSchemaChangedTable($context, $this->id(), $this->downtimeClass());
    }

    public function level(): Level
    {
        return Level::LockHygiene;
    }

    /** Blocking: the schema change's lock on the table is held for the data write's whole duration. */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Blocking;
    }

    /**
     * The three-valued verdict: the flag, else the honest "I could not tell".
     *
     * The lock this rule reasons about only exists inside a transaction, so a statement whose
     * transaction context the canonicalization could not resolve is exactly the one the rule
     * cannot judge — and the boolean it used to read collapses that case into "not in a
     * transaction", which is silence. Silence there is a pass this rule never earned.
     */
    #[Override]
    protected function verdict(MigrationStatementView $statement): ?RuleVerdict
    {
        $flagged = parent::verdict($statement);

        if ($flagged instanceof RuleVerdict) {
            return $flagged;
        }

        return $this->unresolvedContextVerdict($statement);
    }

    /**
     * The undetermined verdict for a migration whose schema change might or might not share a
     * transaction with a data write on the same table — reported once, on the same statement
     * the flag would have landed on, so the two paths address the same line.
     */
    private function unresolvedContextVerdict(MigrationStatementView $statement): ?RuleVerdict
    {
        if (! $this->reportsOn($statement, unresolvedContext: true)) {
            return null;
        }

        $table = $statement->soleTarget(SchemaObjectType::Table);
        $name = $table instanceof StatementTarget ? $table->qualifiedName() : 'a table';

        return RuleVerdict::undetermined(
            'This migration changes the schema of '.$name.' and writes its data, but whether the two '
            .'share a transaction could not be resolved — so whether the schema lock is held across the '
            .'data write is unknown. Split them anyway, or make the transaction boundary explicit; this '
            .'is reported rather than passed over because a held lock is invisible until it is holding.',
            UndeterminedReason::TransactionContextUnknown,
        );
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $this->reportsOn($statement, unresolvedContext: false)) {
            return null;
        }

        $table = $statement->soleTarget(SchemaObjectType::Table);
        $name = $table instanceof StatementTarget ? $table->qualifiedName() : 'a table';

        return 'This migration changes the schema of '.$name.' and writes its data in the same '
            .'transaction, so the schema change\'s exclusive lock on the table is held for the whole data '
            .'write, not just the schema change — and the two cannot be timed out or rolled back '
            .'independently. Split them: change the schema in one migration, and backfill the data in a '
            .'separate migration or a queued job that runs after the first has committed.';
    }

    /**
     * Whether this statement is the one the finding lands on — the FIRST data write in the stream
     * that hits a table some schema-changing statement acts on in the same transaction.
     *
     * Read once, for the flag, the undetermined verdict AND the fix material. The three used to
     * carry their own copies of the same four steps, and a copy is where a report ends up naming a
     * statement its own plan does not describe.
     */
    private function reportsOn(MigrationStatementView $statement, bool $unresolvedContext): bool
    {
        if (! $statement->is(StatementKind::Dml)) {
            return false;
        }

        $stream = $statement->migration->statements;
        $schemaChanged = $this->schemaChangedTables($stream, $statement->migration, $unresolvedContext);

        if ($schemaChanged === []) {
            return false;
        }

        // Reported once, on the first data write in the stream that lands on a schema-changed table.
        $first = $this->firstDmlOnSchemaChangedTable($stream, $schemaChanged);

        return $first instanceof MigrationStatementDigest && $first->index === $statement->statementIndex;
    }

    /**
     * The existing tables a schema-changing statement acts on within a transaction — the
     * tables a data write on which would run under a held schema lock. A table the
     * migration itself created is excluded (uncontended until commit).
     *
     * With `$unresolvedContext`, the same walk over the statements whose transaction context
     * could NOT be resolved. One walk, one definition of "schema change on an existing table";
     * a second copy for the undetermined path would be the place the two silently diverge.
     *
     * @param  list<MigrationStatementDigest>  $stream
     * @return list<string>
     */
    private function schemaChangedTables(array $stream, MigrationContext $migration, bool $unresolvedContext = false): array
    {
        $tables = [];

        foreach ($stream as $digest) {
            // Two disjoint selections over one walk: the statements that DEFINITELY share a
            // transaction (the flag), and the ones whose context could not be resolved (the
            // undetermined). A statement is in exactly one of them, so the two verdicts can
            // never both fire on the same migration.
            $eligible = $unresolvedContext
                ? $digest->transactionContextUnknown()
                : $digest->withinTransaction;

            if (! $eligible) {
                continue;
            }

            if (! in_array($digest->kind, self::SCHEMA_CHANGE_KINDS, true)) {
                continue;
            }

            $tableTargets = array_filter(
                $digest->targets,
                static fn (StatementTarget $target): bool => $target->type === SchemaObjectType::Table,
            );

            foreach ($tableTargets as $target) {
                if (! $migration->createsTable($target->qualifiedName()) && ! in_array($target->qualifiedName(), $tables, true)) {
                    $tables[] = $target->qualifiedName();
                }
            }
        }

        return $tables;
    }

    /**
     * The first `Dml` statement in the stream, within a transaction, whose sole table is
     * one of the schema-changed tables — the statement the single finding is reported on.
     *
     * @param  list<MigrationStatementDigest>  $stream
     * @param  list<string>  $schemaChanged
     */
    private function firstDmlOnSchemaChangedTable(array $stream, array $schemaChanged): ?MigrationStatementDigest
    {
        foreach ($stream as $digest) {
            if ($digest->kind !== StatementKind::Dml) {
                continue;
            }

            // No transaction check here: a non-empty $schemaChanged means a schema change
            // ran within a transaction, and a migration's transaction context is uniform,
            // so every statement in it — this data write included — shares that context.
            $table = $digest->soleTarget(SchemaObjectType::Table);

            if ($table instanceof StatementTarget && in_array($table->qualifiedName(), $schemaChanged, true)) {
                return $digest;
            }
        }

        return null;
    }
}
