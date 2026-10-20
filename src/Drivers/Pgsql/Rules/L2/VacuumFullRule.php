<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L2;

use Override;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Deploy\Contracts\DeclaresOperationClass;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\NoSafeSequenceTemplate;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * `VACUUM FULL` in a migration: a rewrite of the whole table under the strongest lock PostgreSQL has.
 *
 * It writes the table into a new file, rebuilds every index on it, and holds ACCESS EXCLUSIVE from
 * the start of the rewrite to its end. No read and no write gets through for that whole time, and
 * the time grows with the table rather than with the space the rewrite gives back. It also needs
 * disk for a second copy of the table and its indexes while it runs. Named without a table, it
 * does the same to every table of the database, one after the other.
 *
 * The plain `VACUUM` is a different statement and is not reported: it marks dead rows for reuse
 * under SHARE UPDATE EXCLUSIVE, which no read and no write waits behind. The classifier tells the
 * two apart by the word FULL, wherever the statement writes it, so the old spelling and the option
 * list in parentheses reach this rule alike.
 *
 * Whether the statement can run at all is another question: PostgreSQL refuses `VACUUM` inside a
 * transaction block with error 25001, and Laravel wraps a migration in one by default.
 * `PG.L3.VACUUM_IN_TRANSACTION` reports that, so a `VACUUM FULL` in a transaction carries both
 * findings, each about one thing.
 *
 * A `CLUSTER` is the same kind of statement and is reported by `PG.L2.CLUSTER`, which names it.
 */
final class VacuumFullRule extends AbstractPgsqlSafetyRule implements DeclaresOperationClass, ProvidesRemediation
{
    /** The considered `none`: the ways to give space back without the lock are not migrations. */
    private readonly NoSafeSequenceTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new NoSafeSequenceTemplate;
    }

    /**
     * A considered `none`. The plain `VACUUM` may stay in the migration, and `pg_repack` or
     * `pg_squeeze` give the space back online, but both are run by an operator outside the deploy,
     * so there is no sequence of migration statements to hand over.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if ($this->judge($statement) === null) {
            return null;
        }

        return $this->template->payload(
            'sqlens::messages.remediation.no_safe_sequence.vacuum_full',
            'sqlens::messages.remediation.no_safe_sequence.maintenance_verification',
            $this->id(),
            $this->downtimeClass(),
        );
    }

    public function id(): string
    {
        return 'PG.L2.VACUUM_FULL';
    }

    /**
     * The rewrite writes every byte of the table and its indexes into new files, so its cost is
     * measured the way a type change's rewrite is: in bytes on disk, which is what the rewrite
     * threshold weighs the finding by when a deploy knows the table's size.
     */
    public function operationClass(): string
    {
        return 'rewrite';
    }

    public function level(): Level
    {
        return Level::BlockingDdl;
    }

    /** Rewrite: the table's storage is written anew, and the lock holds for as long as that takes. */
    #[Override]
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Rewrite;
    }

    #[Override]
    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $statement->is(StatementKind::RebuildTable) || preg_match('/^VACUUM\b/', $statement->canonical) !== 1) {
            return null;
        }

        return 'VACUUM FULL writes the whole table into a new file and holds an ACCESS EXCLUSIVE lock on it '
            .'until the rewrite is done: no read and no write gets through for the entire run, which grows with '
            .'the table, and the run needs disk for a second copy of the table and its indexes. Without a table '
            .'name it does that to every table in the database, one after the other. A plain VACUUM marks dead '
            .'rows for reuse without that lock, and pg_repack or pg_squeeze rewrite a bloated table online, '
            .'holding the exclusive lock only for a moment at the start and at the end. If the rewrite has to '
            .'happen as VACUUM FULL, run it outside the deploy, in a maintenance window.';
    }
}
