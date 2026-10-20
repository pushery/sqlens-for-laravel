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
 * `CLUSTER` in a migration: the table written anew in the order of an index, under the strongest
 * lock PostgreSQL has.
 *
 * It is a rewrite like `VACUUM FULL`: a new file for the table, every index rebuilt, ACCESS
 * EXCLUSIVE from the start of the rewrite to its end, and disk for a second copy while it runs. No
 * read and no write gets through for that whole time. The order it writes is not kept as rows
 * change, so the statement has to run again to keep its effect, which is one more reason it does
 * not belong in a migration that every deploy and every fresh environment runs.
 *
 * The kind is shared with `VACUUM FULL`, and the lead word tells the two apart, so each finding
 * names the statement the migration wrote. A `CLUSTER` without a table re-clusters every table
 * clustered before; no signature can name those tables, and its migration stays undetermined.
 */
final class ClusterRule extends AbstractPgsqlSafetyRule implements DeclaresOperationClass, ProvidesRemediation
{
    /** The considered `none`: an online re-clustering is run by an operator, not by a migration. */
    private readonly NoSafeSequenceTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new NoSafeSequenceTemplate;
    }

    /**
     * A considered `none`. `pg_repack` writes a table in an index's order while it stays in use, but
     * an operator runs it outside the deploy, so there is no sequence of migration statements to hand
     * over.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if ($this->judge($statement) === null) {
            return null;
        }

        return $this->template->payload(
            'sqlens::messages.remediation.no_safe_sequence.cluster',
            'sqlens::messages.remediation.no_safe_sequence.maintenance_verification',
            $this->id(),
            $this->downtimeClass(),
        );
    }

    public function id(): string
    {
        return 'PG.L2.CLUSTER';
    }

    /** A rewrite of the table and its indexes, weighed in bytes on disk like every rewrite. */
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
        if (! $statement->is(StatementKind::RebuildTable) || preg_match('/^CLUSTER\b/', $statement->canonical) !== 1) {
            return null;
        }

        return 'CLUSTER writes the whole table into a new file in the order of an index and holds an ACCESS '
            .'EXCLUSIVE lock on it until the rewrite is done: no read and no write gets through for the entire '
            .'run, which grows with the table, and the run needs disk for a second copy of the table and its '
            .'indexes. The order is not kept as rows change, so the statement has to run again to keep its '
            .'effect. pg_repack writes a table in an index\'s order while it stays in use, holding the exclusive '
            .'lock only for a moment at the start and at the end. If the rewrite has to happen as CLUSTER, run '
            .'it outside the deploy, in a maintenance window.';
    }
}
