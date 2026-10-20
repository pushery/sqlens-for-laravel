<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L2;

use Override;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Deploy\Contracts\DeclaresOperationClass;
use Pushery\SQLens\Drivers\Pgsql\Remediation\ConcurrentlyTemplate;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * `REINDEX` without CONCURRENTLY: an index rebuilt while every write to its table waits.
 *
 * It holds SHARE on the table for the whole rebuild, so every INSERT, UPDATE and DELETE waits, and
 * ACCESS EXCLUSIVE on each index it rebuilds, so every read that would use one waits as well.
 * `REINDEX TABLE` does that for every index of the table, one after the other.
 *
 * `REINDEX … CONCURRENTLY` builds each replacement beside the old index and swaps them, so neither
 * reads nor writes wait. PostgreSQL refuses it inside a transaction block, which
 * `PG.L3.CONCURRENTLY_IN_TRANSACTION` reports, and the fix material this rule hands over moves the
 * statement into a migration of its own.
 */
final class ReindexNotConcurrentRule extends AbstractPgsqlSafetyRule implements DeclaresOperationClass, ProvidesRemediation
{
    /** The concurrent rebuild this rule points at, built once. */
    private readonly ConcurrentlyTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new ConcurrentlyTemplate;
    }

    public function id(): string
    {
        return 'PG.L2.REINDEX_NOT_CONCURRENT';
    }

    /** The statement rebuilt concurrently, in a migration whose transaction is switched off. */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if (! $this->rebuildsWhileWritesWait($statement)) {
            return null;
        }

        return $this->template->forReindex($statement, $this->id(), $this->downtimeClass());
    }

    /**
     * A rebuild walks the table's rows and sorts them again, as a build does, so it is weighed on the
     * same line as `PG.L2.INDEX_NOT_CONCURRENT`.
     */
    public function operationClass(): string
    {
        return 'index_build';
    }

    public function level(): Level
    {
        return Level::BlockingDdl;
    }

    /** Blocking: writes wait for the whole rebuild, and the table's storage is not rewritten. */
    #[Override]
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Blocking;
    }

    #[Override]
    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $this->rebuildsWhileWritesWait($statement)) {
            return null;
        }

        return 'REINDEX without CONCURRENTLY holds a SHARE lock on the table until the rebuild is done, so every '
            .'write to it waits, and an ACCESS EXCLUSIVE lock on each index it rebuilds, so every read that would '
            .'use one waits as well; REINDEX TABLE does that for every index of the table. REINDEX ... '
            .'CONCURRENTLY builds each replacement beside the old index and blocks neither reads nor writes. It '
            .'cannot run inside a transaction, so set public $withinTransaction = false; on the migration class.';
    }

    /** Whether this is the rebuild the finding and the fix material are about: a REINDEX that is not concurrent. */
    private function rebuildsWhileWritesWait(MigrationStatementView $statement): bool
    {
        return $statement->is(StatementKind::Reindex)
            && preg_match('/\bCONCURRENTLY\b/', $statement->canonical) !== 1;
    }
}
