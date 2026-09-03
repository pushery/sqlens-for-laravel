<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L1;

use Override;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Mysql\DowntimeClass\MysqlDowntimeClassSource;
use Pushery\SQLens\Drivers\Mysql\DowntimeClass\NonDdlImpact;
use Pushery\SQLens\Drivers\Mysql\Rules\AbstractMysqlRule;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\DeployWindowDropTemplate;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * `DROP TABLE` in a migration's `up()`, on MySQL.
 *
 * ## Why this rule did not exist until now, which is the part worth recording
 *
 * It was not a decision. The destructive level-1 group was built driver by driver and MySQL never
 * got its turn: measured across every shipped rule, PostgreSQL carried four L1 rules and MySQL
 * carried one. So `DROP TABLE invoices` produced two findings on PostgreSQL and **none at all** on
 * MySQL — a green run over the most common irreversible mistake a migration can make, on an engine
 * the README promises without qualification.
 *
 * Nothing was suppressing it and nothing was undetermined. There was simply no rule to fire.
 *
 * ## Why it is its own rule rather than the PostgreSQL one registered twice
 *
 * The destruction is the same; the recovery is not, and the recovery is what a reader needs. On
 * MySQL `DROP TABLE` is DDL, so it causes an **implicit commit** — Laravel's MySQL grammar reports
 * `supportsSchemaTransactions() === false`, and the server commits regardless of what the migrator
 * would have wrapped. The table is gone the instant the statement runs, whatever fails afterwards
 * in the same migration.
 *
 * A rule that said the PostgreSQL sentence here would be telling a reader their transaction
 * protects them. It does not. That is the same reason {@see TruncateRule}
 * exists separately, and the reasoning is deliberately identical rather than freshly invented.
 *
 * ## What it does NOT re-decide
 *
 * The same-migration exception and the opt-in behavior follow the PostgreSQL rule exactly, because
 * those parts genuinely are engine-neutral: a table this migration just created never held data a
 * deploy would miss, and `#[SqlensAllowDestructive]` records a review rather than silencing the
 * finding. The staged-drop remediation is shared for the same reason — the ordering that makes a
 * drop safe is about the application in front of the database, not about the engine.
 */
final class DropTableRule extends AbstractMysqlRule implements ProvidesRemediation
{
    private readonly MysqlDowntimeClassSource $downtimeClasses;

    /** The staged drop this rule points at, built once — the same sequence its PostgreSQL sibling offers. */
    private readonly DeployWindowDropTemplate $template;

    public function __construct(string $projectRoot, ?MysqlDowntimeClassSource $downtimeClasses = null)
    {
        parent::__construct($projectRoot);

        $this->downtimeClasses = $downtimeClasses ?? new MysqlDowntimeClassSource;
        $this->template = new DeployWindowDropTemplate;
    }

    public function id(): string
    {
        return 'MY.L1.DROP_TABLE';
    }

    public function level(): Level
    {
        return Level::Destructive;
    }

    /**
     * From the non-DDL derivation: `DROP TABLE` is not an `ALTER`, so the online-DDL matrix has no
     * entry for it and never will. {@see NonDdlImpact::TableRemoval} carries the reasoning and the
     * caveat about a very large `.ibd`.
     */
    #[Override]
    public function downtimeClass(): DowntimeClass
    {
        return $this->downtimeClasses->forNonDdl(NonDdlImpact::TableRemoval);
    }

    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if ($this->judge($statement) === null) {
            return null;
        }

        return $this->template->forTable($this->tableContext($statement), $this->id(), $this->downtimeClass());
    }

    /**
     * The table this statement names, as the classifier resolved it.
     *
     * @return array<string, string>
     */
    private function tableContext(MigrationStatementView $statement): array
    {
        $table = $statement->soleTarget(SchemaObjectType::Table);

        return $table instanceof StatementTarget ? ['table' => $table->qualifiedName()] : [];
    }

    #[Override]
    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $statement->is(StatementKind::DropTable)) {
            return null;
        }

        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget && $statement->migration->createsTable($table->qualifiedName())) {
            return null;
        }

        return 'DROP TABLE in up() is irreversible data loss — and on MySQL there is no transaction to '
            .'take it back. DROP TABLE is DDL here, so it causes an implicit commit: the table and every '
            .'row in it are gone the instant the statement runs, whatever fails later in the same '
            .'migration, and down() is the only way back — one that can re-create the table but not its '
            .'rows. Retire the reads in a shipped release first, then drop it later. If the loss is '
            .'intended, annotate the migration with #[SqlensAllowDestructive] and a reason — that does '
            .'not hide the finding, it records who decided.';
    }
}
