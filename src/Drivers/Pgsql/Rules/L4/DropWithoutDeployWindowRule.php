<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L4;

use Override;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Findings\Confidence;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\DeployWindowDropTemplate;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A `DROP TABLE` or `DROP COLUMN` breaks any still-running old application version that
 * references the object the instant the migration lands. Level 1 asks about the DATA
 * (it is gone for good); this level asks about the DEPLOY WINDOW: a drop is safe only as
 * the CONTRACT half of an expand/contract, where an earlier deploy already shipped the
 * code that stops using the object, and this later deploy only removes it.
 *
 * The rule fires on a `DROP TABLE`/`DROP COLUMN` that is not prepared this way. It is
 * openly `heuristic`: SQLens sees the SQL, not the application code, so it cannot prove
 * the old version is gone — the finding spells out the safe sequence (deploy 1: ship code
 * that no longer uses the object; deploy 2: drop it) as a prompt to check, never as a
 * verdict. It stays silent when the object is created in the SAME migration (it never
 * existed for a prior deploy). A `#[SqlensAllowDestructive]` opt-in no longer silences it
 * either: the finding is produced, and that same explicit "I have reviewed this
 * destructive drop" signal is applied at the reporting layer as a named, visible
 * suppression — covering both the level-1 and this level-4 concern of the one operation,
 * its reason shown — so the deploy-window risk is never hidden.
 *
 * It coexists with `PG.L1.DROP_TABLE`/`PG.L1.DROP_COLUMN` on the same statement — both
 * axes may fire, the reporter shows level 1 and level 4 as separate statements, and the
 * texts do not repeat. Detection is on the classification, never Laravel's raw grammar.
 */
final class DropWithoutDeployWindowRule extends AbstractPgsqlSafetyRule implements ProvidesRemediation
{
    /** The staged sequence this rule hands over, built once — it resolves the citation from the register. */
    private readonly DeployWindowDropTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new DeployWindowDropTemplate;
    }

    /**
     * The staged sequence — the same drop, with everything that has to happen before it.
     *
     * The KIND decides which statement the sequence ends on, read through the same classification
     * accessor {@see judge()} uses rather than a second look at the SQL. A table drop names only its
     * table; a column drop names both, and both come from targets the classifier resolved.
     *
     * Null for anything else, which the collector never asks about — it only offers statements this
     * rule flagged — but a template invented for an unclassified statement is exactly what a fix
     * must never be.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
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

    public function id(): string
    {
        return 'PG.L4.DROP_WITHOUT_DEPLOY_WINDOW';
    }

    public function level(): Level
    {
        return Level::BackwardCompatibility;
    }

    /** Online: the deploy-window break is a compatibility concern; the lock is the level-1 rule's axis. */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    /** Heuristic: the tool sees the SQL, not whether the old app version still uses the object. */
    #[Override]
    public function confidence(): Confidence
    {
        return Confidence::Heuristic;
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $statement->is(StatementKind::DropTable) && ! $statement->is(StatementKind::DropColumn)) {
            return null;
        }

        // An object created in this same migration never existed for a prior deploy, so no
        // old application version can be broken by dropping it here.
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
