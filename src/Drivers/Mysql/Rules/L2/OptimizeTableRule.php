<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L2;

use Override;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Contracts\DerivesDowntimeClass;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Deploy\Contracts\DeclaresOperationClass;
use Pushery\SQLens\Drivers\Mysql\DowntimeClass\MysqlDowntimeClassSource;
use Pushery\SQLens\Drivers\Mysql\Rules\AbstractMysqlRule;
use Pushery\SQLens\Engine\ResolvedServerVersion;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\DowntimeUndetermined;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\NoSafeSequenceTemplate;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * `OPTIMIZE TABLE` in a migration: a rebuild of the whole table under a maintenance name.
 *
 * On InnoDB the statement is a table rebuild, the same physical work as `ALTER TABLE … FORCE`, so it
 * costs time and disk in proportion to the table and not to the space it gives back. How the
 * rebuild treats the table's writers depends on one fact about the table, and the online DDL matrix
 * records it as the condition on its `optimize_table` entry: without a FULLTEXT index the rebuild
 * runs in place and the table stays writable, with one it becomes a copy and every write waits for
 * the whole run.
 *
 * A lint run reads the migration and not the table, so it cannot tell which of the two a deploy
 * meets. The downtime class says that rather than picking the cheap case: it is the matrix's answer
 * for the blind context, undetermined with the condition named. The message names both cases and
 * the statement that settles the question at the server: `ALTER TABLE … FORCE, ALGORITHM=INPLACE,
 * LOCK=NONE` rebuilds the same way and is refused where the rebuild would be a copy.
 *
 * A replica repeats the rebuild, because the statement is written to the binary log unless it says
 * `NO_WRITE_TO_BINLOG` or `LOCAL`. Either spelling reaches this rule as well.
 */
final class OptimizeTableRule extends AbstractMysqlRule implements DeclaresOperationClass, DerivesDowntimeClass, ProvidesRemediation
{
    /** The operation the online DDL matrix answers this statement with. */
    private const string OPERATION = 'optimize_table';

    private readonly MysqlDowntimeClassSource $downtimeClasses;

    /** The considered `none`: whether the rebuild blocks writes is a fact about the table. */
    private readonly NoSafeSequenceTemplate $template;

    public function __construct(string $projectRoot, ?MysqlDowntimeClassSource $downtimeClasses = null)
    {
        parent::__construct($projectRoot);

        $this->downtimeClasses = $downtimeClasses ?? new MysqlDowntimeClassSource;
        $this->template = new NoSafeSequenceTemplate;
    }

    /**
     * A considered `none`. The statement that keeps the table writable, `ALTER TABLE … FORCE,
     * ALGORITHM=INPLACE, LOCK=NONE`, is still a rebuild of the whole table and is refused on a table
     * with a FULLTEXT index, so it is named in the note rather than handed over as a sequence. The
     * class it carries is the one this rule derived for the same statement.
     */
    #[Override]
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if ($this->judge($statement) === null) {
            return null;
        }

        return $this->template->payload(
            'sqlens::messages.remediation.no_safe_sequence.optimize_table',
            'sqlens::messages.remediation.no_safe_sequence.maintenance_verification',
            $this->id(),
            $this->knownDowntimeClass($this->downtimeClassFor($statement)),
        );
    }

    public function id(): string
    {
        return 'MY.L2.OPTIMIZE_TABLE';
    }

    /**
     * A rebuild writes every byte of the table and its indexes again, in place or as a copy, so its
     * cost is measured the way every other rewrite's is: in bytes on disk, which is what the rewrite
     * threshold weighs a finding by when a deploy knows the table's size.
     */
    public function operationClass(): string
    {
        return 'rewrite';
    }

    public function level(): Level
    {
        return Level::BlockingDdl;
    }

    /** From the matrix, for the one operation this statement is. */
    public function downtimeClassFor(MigrationStatementView $statement): DowntimeClass|DowntimeUndetermined|null
    {
        if (! $statement->is(StatementKind::RebuildTable)) {
            return null;
        }

        return $this->downtimeClasses->forCandidateOperations(
            [self::OPERATION],
            $statement->serverVersion ?? ResolvedServerVersion::unresolvable(),
        )->derived();
    }

    #[Override]
    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $statement->is(StatementKind::RebuildTable)) {
            return null;
        }

        return 'OPTIMIZE TABLE rebuilds the whole table, the same work as ALTER TABLE ... FORCE, so the run grows '
            .'with the table and not with the space it gives back, and it needs disk for a second copy. InnoDB runs '
            .'the rebuild in place and keeps the table writable only while the table has no FULLTEXT index; with '
            .'one, the rebuild is a copy and every write waits for the whole run. This rule reads the migration, so '
            .'it cannot see which of the two the table is. A replica repeats the rebuild unless the statement says '
            .'NO_WRITE_TO_BINLOG. A migration is the wrong place for it: run it outside the deploy, in a maintenance '
            .'window. If the table must stay writable, issue ALTER TABLE ... FORCE, ALGORITHM=INPLACE, LOCK=NONE '
            .'instead, which rebuilds the same way and is refused where the rebuild would be a copy.';
    }
}
