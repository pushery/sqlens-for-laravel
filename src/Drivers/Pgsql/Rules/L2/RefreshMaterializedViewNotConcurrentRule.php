<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L2;

use Override;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Pgsql\Remediation\ConcurrentlyTemplate;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * `REFRESH MATERIALIZED VIEW` without CONCURRENTLY: every read of the view waits for its query.
 *
 * The ordinary refresh holds ACCESS EXCLUSIVE on the view while it runs the view's query again and
 * replaces what the view holds, so a page that reads the view stalls for the whole run. The
 * concurrent refresh takes an EXCLUSIVE lock instead, which lets every read through; it compares
 * the new result with the old one row by row and needs a unique index on the view to do that.
 *
 * Unlike `CREATE INDEX CONCURRENTLY` and `REINDEX … CONCURRENTLY`, PostgreSQL runs the concurrent
 * refresh inside a transaction block, so the fix stays in the migration and its transaction.
 *
 * No operation class: what the refresh costs is its query, and the size of the view says little
 * about that, so there is no threshold for the escalator to weigh it against.
 */
final class RefreshMaterializedViewNotConcurrentRule extends AbstractPgsqlSafetyRule implements ProvidesRemediation
{
    /** The concurrent refresh this rule points at, built once. */
    private readonly ConcurrentlyTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new ConcurrentlyTemplate;
    }

    public function id(): string
    {
        return 'PG.L2.REFRESH_MATERIALIZED_VIEW_NOT_CONCURRENT';
    }

    /** The statement refreshed concurrently, with the two facts about the view it depends on as preconditions. */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if (! $this->refreshesWhileReadsWait($statement)) {
            return null;
        }

        return $this->template->forRefreshMaterializedView($statement, $this->id(), $this->downtimeClass());
    }

    public function level(): Level
    {
        return Level::BlockingDdl;
    }

    /** Blocking: reads of the view wait for the whole refresh, and nothing else is rewritten. */
    #[Override]
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Blocking;
    }

    #[Override]
    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $this->refreshesWhileReadsWait($statement)) {
            return null;
        }

        return 'REFRESH MATERIALIZED VIEW without CONCURRENTLY holds an ACCESS EXCLUSIVE lock on the view until '
            .'its query has run again, so every read of the view waits for the whole refresh. REFRESH '
            .'MATERIALIZED VIEW CONCURRENTLY keeps the view readable while it runs and may stay inside the '
            .'migration\'s transaction. It needs a unique index on the view over plain columns that covers every '
            .'row, and the view must already hold data.';
    }

    /** Whether this is the refresh the finding and the fix material are about: one that is not concurrent. */
    private function refreshesWhileReadsWait(MigrationStatementView $statement): bool
    {
        return $statement->is(StatementKind::RefreshMaterializedView)
            && preg_match('/\bCONCURRENTLY\b/', $statement->canonical) !== 1;
    }
}
