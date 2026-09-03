<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L4;

use Override;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Mysql\Rules\AbstractMysqlRule;
use Pushery\SQLens\Findings\Confidence;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\DeployWindowDropTemplate;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A `DROP TABLE` or `DROP COLUMN` breaks any still-running old application version that references
 * the object the instant the migration lands — on MySQL exactly as on PostgreSQL.
 *
 * ## Why this one is ALLOWED to read like its PostgreSQL sibling
 *
 * Its two level-1 neighbors are deliberately their own rules with their own sentences, because
 * MySQL's DDL is not transactional and a reader told the PostgreSQL story would believe a
 * transaction protects them. **This rule is the opposite case, and saying so is the point.**
 *
 * The deploy window is not a property of the database. It is a property of what is still running in
 * front of it: an old application version that references the object. Nothing about that changes
 * with the engine, so inventing a MySQL-flavored difference here would be writing a distinction
 * that does not exist — the mirror image of the mistake the level-1 rules avoid.
 *
 * ## Why it did not exist until now
 *
 * The same reason its level-1 neighbors did not: the group was built driver by driver and MySQL
 * never got its turn. Measured before it was built, `DROP TABLE invoices` produced
 * `MY.L1.DROP_TABLE` alone, where PostgreSQL produced both its level-1 finding AND this one.
 *
 * The parity guard that should have caught it was scoped to level 1, on the reasoning that higher
 * levels are engine-shaped. That is true of levels 2, 3 and 5 — and level 4 is mixed:
 * `ENUM_ADD_VALUE` and `CONSTRAINT_VALIDATION_PENDING` really are PostgreSQL mechanics, and this
 * rule is not. The scope moves with this change.
 *
 * ## What it does NOT re-decide
 *
 * The same-migration exemption, the heuristic stance, and the interaction with the destructive
 * opt-in all follow the PostgreSQL rule exactly, because all three are engine-neutral too. It
 * coexists with `MY.L1.DROP_TABLE`/`MY.L1.DROP_COLUMN` on one statement: level 1 asks whether the
 * DATA is expendable, this level asks whether an old reader is still out there.
 */
final class DropWithoutDeployWindowRule extends AbstractMysqlRule implements ProvidesRemediation
{
    /** The staged sequence this rule hands over, built once — shared with the PostgreSQL sibling. */
    private readonly DeployWindowDropTemplate $template;

    public function __construct(string $projectRoot)
    {
        parent::__construct($projectRoot);

        $this->template = new DeployWindowDropTemplate;
    }

    public function id(): string
    {
        return 'MY.L4.DROP_WITHOUT_DEPLOY_WINDOW';
    }

    public function level(): Level
    {
        return Level::BackwardCompatibility;
    }

    /**
     * HEURISTIC, and the message says so in its own words.
     *
     * The rule sees the SQL and not the application, so it cannot prove an old version is still
     * reading the object — it can only tell that nothing in this migration says otherwise. Claiming
     * `deterministic` here would overstate a prompt as a verdict, which is the failure the
     * confidence axis exists to prevent. The PostgreSQL sibling says the same for the same reason.
     */
    #[Override]
    public function confidence(): Confidence
    {
        return Confidence::Heuristic;
    }

    /** Online: the deploy-window break is a compatibility concern; the lock is the level-1 rule's axis. */
    #[Override]
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if ($this->judge($statement) === null) {
            return null;
        }

        $context = [];

        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget) {
            $context['table'] = $table->qualifiedName();
        }

        $column = $statement->soleTarget(SchemaObjectType::Column);

        if ($column instanceof StatementTarget) {
            $context['column'] = $column->qualifiedName();
        }

        return match (true) {
            $statement->is(StatementKind::DropColumn) => $this->template->forColumn($context, $this->id(), $this->downtimeClass()),
            $statement->is(StatementKind::DropTable) => $this->template->forTable($context, $this->id(), $this->downtimeClass()),
            default => null,
        };
    }

    #[Override]
    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $statement->is(StatementKind::DropTable) && ! $statement->is(StatementKind::DropColumn)) {
            return null;
        }

        // An object created in this same migration never existed for a prior deploy, so no old
        // application version can be broken by dropping it here.
        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget && $statement->migration->createsTable($table->qualifiedName())) {
            return null;
        }

        return 'Dropping this object breaks any running old application version that still references it '
            .'the moment the migration lands. Make it the second half of an expand/contract: deploy 1 '
            .'ships code that no longer uses the object, and only a LATER deploy runs this drop. If the '
            .'drop is intentional and the old code is already gone, mark the migration '
            .'#[SqlensAllowDestructive] to say so. SQLens reads only the SQL, not your application code, '
            .'so treat this as a prompt to confirm the window, not a proof that it is missing.';
    }
}
