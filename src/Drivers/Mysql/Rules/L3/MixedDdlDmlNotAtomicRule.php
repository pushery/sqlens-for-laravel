<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L3;

use Override;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Mysql\DowntimeClass\MysqlDowntimeClassSource;
use Pushery\SQLens\Drivers\Mysql\DowntimeClass\NonDdlImpact;
use Pushery\SQLens\Drivers\Mysql\Remediation\AtomicitySplitTemplate;
use Pushery\SQLens\Drivers\Mysql\Rules\AbstractMysqlRule;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Subjects\MigrationStatementDigest;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * A migration that changes the schema and then writes data — which on MySQL is not one operation,
 * whatever the developer assumed.
 *
 * ## Why this is a MySQL rule and not the driver-neutral one registered here
 *
 * The driver-neutral `GEN.L3.DML_ON_SCHEMA_CHANGED_TABLE` judges a different shape: a schema change
 * and a data write in ONE TRANSACTION, where the ALTER's lock is held for the whole backfill. That
 * is a PostgreSQL hazard, and on MySQL it cannot happen — measured, not assumed: Laravel's MySQL
 * grammar reports `supportsSchemaTransactions() === false`, so the migrator never wraps a MySQL
 * migration in a transaction at all. There is no transaction to hold a lock across, so the neutral
 * rule correctly stays silent, and registering it here proves nothing.
 *
 * MySQL's version of the hazard has a different cause and a different consequence:
 *
 * > **Every DDL statement causes an implicit commit.** The schema change is already committed by the
 * > time the data write runs. If the write then fails, the migration is left half applied — schema
 * > changed, data not — and nothing rolls back. `down()` is the only way out, and it has to undo a
 * > state that never existed in anyone's plan.
 *
 * Reusing the neutral message here would name the wrong cause. It would tell a reader to worry about
 * a lock, when what they should worry about is a migration that cannot fail cleanly.
 *
 * ## Reported once, on the write
 *
 * The finding sits on the FIRST data write that follows a schema change, not on every one and not on
 * the schema change itself. The write is where the migration stops being recoverable, and a
 * migration that does three of them has one problem, not three.
 *
 * ## Table-independent, deliberately
 *
 * The neutral rule asks whether the write touches the table the schema change touched. This one does
 * not, and that is not laxness: the implicit commit does not care which table either statement
 * names. A migration that alters `orders` and then backfills `order_lines` is exactly as
 * un-rollbackable as one that does both to `orders`.
 */
final class MixedDdlDmlNotAtomicRule extends AbstractMysqlRule implements ProvidesRemediation
{
    private readonly MysqlDowntimeClassSource $downtimeClasses;

    /** The split this rule points at — MySQL's, argued from the implicit commit rather than a lock. */
    private readonly AtomicitySplitTemplate $template;

    public function __construct(string $projectRoot, ?MysqlDowntimeClassSource $downtimeClasses = null)
    {
        parent::__construct($projectRoot);

        $this->downtimeClasses = $downtimeClasses ?? new MysqlDowntimeClassSource;
        $this->template = new AtomicitySplitTemplate;
    }

    public function id(): string
    {
        return 'MY.L3.MIXED_DDL_DML_NOT_ATOMIC';
    }

    /**
     * The split — and deliberately NOT the PostgreSQL split template under a different caller.
     *
     * That one argues from locks held to commit, an argument that does not exist here: Laravel's
     * MySQL grammar opens no transaction at all, so there is no lock to hold across anything. The
     * reason to split on MySQL is the implicit commit, and the consequence is a migration that
     * cannot fail cleanly rather than one that queues traffic. A reader handed the lock argument
     * would go looking for a lock that is not there.
     *
     * Silent for a statement this rule does not flag: the material is about the SHAPE of the
     * migration, and the migration's shape is exactly what {@see judge()} reads. Calling it for its
     * null-ness rather than restating its three conditions is what keeps the two from disagreeing
     * about which write carries the finding — the rule reports once, on the first one.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if ($this->judge($statement) === null) {
            return null;
        }

        return $this->template->payload($this->id(), $this->downtimeClass());
    }

    public function level(): Level
    {
        return Level::LockHygiene;
    }

    /**
     * From the non-DDL derivation: the statement this finding sits on is a data write mixed into a
     * stream that also changes the schema, which is {@see NonDdlImpact::MixedWithSchemaChange} —
     * `blocking`. Never a literal here; the derivation is the one place that decides it.
     */
    #[Override]
    public function downtimeClass(): DowntimeClass
    {
        return $this->downtimeClasses->forNonDdl(NonDdlImpact::MixedWithSchemaChange);
    }

    #[Override]
    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $statement->is(StatementKind::Dml)) {
            return null;
        }

        if (! $this->followsASchemaChange($statement) || $this->anEarlierWriteAlreadyReported($statement)) {
            return null;
        }

        return 'This migration changes the schema and then writes data, and on MySQL that is not one operation. '
            .'Every DDL statement causes an implicit commit, so the schema change is already committed by the time '
            .'this write runs — and if the write fails, the migration is left half applied: schema changed, data '
            .'not, with nothing to roll back. down() is then the only way out, and it has to undo a state nobody '
            .'planned for. Split them: one migration changes the schema, a later one (or a queued job) fills the '
            .'data, so each step either completes or leaves nothing behind.';
    }

    /** Whether a schema change runs BEFORE this statement in the migration's own stream. */
    private function followsASchemaChange(MigrationStatementView $statement): bool
    {
        return array_any(
            $statement->migration->statements,
            fn (MigrationStatementDigest $other): bool => $other->index < $statement->statementIndex
                && $this->isSchemaChange($other),
        );
    }

    /**
     * Whether an earlier data write in this migration already carries the finding.
     *
     * One migration, one finding: a backfill written as three statements has one problem, and three
     * findings pointing at the same cause is how a report teaches its reader to skim.
     */
    private function anEarlierWriteAlreadyReported(MigrationStatementView $statement): bool
    {
        $sawSchemaChange = false;

        foreach ($statement->migration->statements as $other) {
            if ($other->index >= $statement->statementIndex) {
                break;
            }

            if ($this->isSchemaChange($other)) {
                $sawSchemaChange = true;

                continue;
            }

            if ($sawSchemaChange && $other->kind === StatementKind::Dml) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a statement in the stream changes the schema.
     *
     * Read off the classified KIND rather than the SQL: what a statement does is the classifier's
     * answer, and a rule re-deriving it from text would be a second opinion waiting to disagree.
     * Everything that is not data manipulation and not unclassified is a schema change here —
     * inverted deliberately, so a statement kind added later is covered without anyone remembering
     * to extend a list. An UNCLASSIFIED statement is excluded: it might be either, and "might" is
     * not the basis for a finding.
     */
    private function isSchemaChange(MigrationStatementDigest $statement): bool
    {
        return $statement->kind instanceof StatementKind
            && $statement->kind !== StatementKind::Dml
            && $statement->kind !== StatementKind::Unknown;
    }
}
