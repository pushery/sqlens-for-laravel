<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L1;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\DeployWindowDropTemplate;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * `ALTER TABLE … DROP COLUMN` in a migration's `up()` deletes the column's data the
 * moment the deploy is past — the access to it is gone irreversibly, even though
 * PostgreSQL only marks the column dropped rather than rewriting the table. Level 1
 * catches that data loss.
 *
 * This rule speaks ONLY to the loss. The separate concern — that dropping a column
 * still read by a running old app version needs a deploy window, "ship the code that
 * stops using it first" — belongs to `PG.L4.DROP_WITHOUT_DEPLOY_WINDOW`, and this
 * finding deliberately does not repeat that advice, so the two rules do not say the
 * same thing twice about one statement.
 *
 * It stays silent when the table is one this same migration created (its columns never
 * held persistent data). A migration that MEANT the drop declares it with
 * `#[SqlensAllowDestructive]`; that no longer silences the rule — the finding is
 * produced and the opt-in becomes a named, visible suppression at the reporting layer,
 * its reason shown, so the loss is never hidden. CASCADE is named when present.
 * Detection is on the canonical form and the classified target, never Laravel's raw
 * grammar.
 *
 * A column ADDED and then dropped within one migration on a PRE-EXISTING table is not
 * caught by the table-level exception — the classifier does not model per-column
 * additions — but that shape is rare and the loss is genuinely nil, so it is a known,
 * documented limit rather than a false positive worth column-level bookkeeping.
 */
final class DropColumnRule extends AbstractPgsqlSafetyRule implements ProvidesRemediation
{
    /** The staged drop this rule points at, built once. */
    private readonly DeployWindowDropTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new DeployWindowDropTemplate;
    }

    public function id(): string
    {
        return 'PG.L1.DROP_COLUMN';
    }

    /**
     * The staged drop, on the DATA axis.
     *
     * The same sequence its level-4 sibling hands over for the same statement — the ordering is
     * what protects the deploy, and a precondition inside it says plainly that it does nothing for
     * the rows: once the drop runs, what was in the column is gone, and no ordering fixes that.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if (! $statement->is(StatementKind::DropColumn)) {
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

        return $this->template->forColumn($context, $this->id(), $this->downtimeClass());
    }

    public function level(): Level
    {
        return Level::Destructive;
    }

    /**
     * Online: DROP COLUMN is metadata-only — no scan, no rewrite. The danger is the
     * irreversible data loss, which is the LEVEL, not the deploy-time impact.
     */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $statement->is(StatementKind::DropColumn)) {
            return null;
        }

        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget && $statement->migration->createsTable($table->qualifiedName())) {
            return null;
        }

        $cascade = preg_match('/\bCASCADE\b/', $statement->canonical) === 1
            ? ' It uses CASCADE, so every object that depends on the column — a view, an index — is dropped with it.'
            : '';

        return 'DROP COLUMN in up() irreversibly deletes the column\'s data once the deploy is past. '
            .'PostgreSQL only marks the column dropped — there is no table rewrite — but the data behind '
            .'it is gone for good.'.$cascade.' If the loss is intended, annotate the migration with '
            .'#[SqlensAllowDestructive] and a reason.';
    }
}
