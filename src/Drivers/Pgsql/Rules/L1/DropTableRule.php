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
 * A `DROP TABLE` in a migration's `up()` is irreversible data loss the moment the
 * deploy is past — there is no WHERE clause to undo it, and the rollback (if there is
 * one at all) has to re-create the table from nothing. Level 1 is where that lives:
 * the destruction a migration did not mean to ship.
 *
 * It stays silent on one genuine non-loss: a table this same migration created and
 * then dropped never held persistent data, so dropping it loses nothing a deploy would
 * miss.
 *
 * A migration that MEANT the drop declares it with `#[SqlensAllowDestructive]`. That no
 * longer silences the rule: the finding is still produced, and the opt-in is applied at
 * the reporting layer as a NAMED, VISIBLE suppression with its reason shown — so a run
 * always shows the destruction happened. The opt-in changes the presentation, not the
 * fact.
 *
 * CASCADE is called out by name when present: it widens the loss to every dependent
 * object — views, foreign keys — so a reader is not surprised by what else went with
 * the table.
 *
 * Only `up()` statements reach a rule in a normal lint (the capture reads the up
 * section); a `DROP TABLE` in `down()` is a rollback undoing an `up()` create and is
 * not this rule's concern.
 *
 * Detection is on the canonical form and the classified target, never Laravel's raw
 * grammar.
 */
final class DropTableRule extends AbstractPgsqlSafetyRule implements ProvidesRemediation
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
        return 'PG.L1.DROP_TABLE';
    }

    /**
     * The staged drop — the same sequence the deploy-window rule hands over, from the other axis.
     *
     * Both rules fire on this statement and ask different questions: that one asks whether an old
     * application version still uses the object, this one asks whether the DATA is expendable. The
     * ordering that answers the first is the only thing either can offer, so pointing at the same
     * sequence is right — and a second copy of it here would be two versions of one plan on one
     * statement.
     *
     * The sequence names the destructive opt-in as its LAST step, which is what keeps this from
     * becoming a way past the level-1 gate: the attribute records a review, it does not silence the
     * finding.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if (! $statement->is(StatementKind::DropTable)) {
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

    public function level(): Level
    {
        return Level::Destructive;
    }

    /**
     * Online: a drop takes a brief exclusive lock but does not block for a scan or a
     * rewrite. Its danger is the irreversible data loss, which is the LEVEL, not the
     * deploy-time impact the downtime class models — the two axes stay separate.
     */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $statement->is(StatementKind::DropTable)) {
            return null;
        }

        // A table born and dropped inside this one migration never held data a deploy
        // would miss — dropping it is not the loss this rule warns about.
        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget && $statement->migration->createsTable($table->qualifiedName())) {
            return null;
        }

        $cascade = preg_match('/\bCASCADE\b/', $statement->canonical) === 1
            ? ' It uses CASCADE, so every object that depends on the table — views, foreign keys — is dropped with it.'
            : '';

        return 'DROP TABLE in up() is irreversible data loss once the deploy is past: the table and all '
            .'its rows are gone, and no WHERE clause brings them back.'.$cascade.' If the drop is intended, '
            .'annotate the migration with #[SqlensAllowDestructive] and a reason.';
    }
}
