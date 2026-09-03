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
use Pushery\SQLens\Remediation\NoSafeSequenceTemplate;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * `TRUNCATE` in a migration's `up()` empties the table with no confirmation and no
 * WHERE clause to undo it — data loss the moment the deploy is past — and it takes an
 * ACCESS EXCLUSIVE lock, which conflicts with every other lock and so blocks all
 * access to the table while it runs. Level 1 catches the destruction a migration did
 * not mean to ship.
 *
 * It stays silent when a helper table this same migration created holds no data a
 * deploy would miss. A migration that MEANT the truncate declares it with
 * `#[SqlensAllowDestructive]`; that no longer silences the rule — the finding is
 * produced and the opt-in becomes a named, visible suppression at the reporting layer,
 * its reason shown, so the loss is never hidden.
 *
 * CASCADE is named when present — it truncates every table with a foreign key to this
 * one, so the loss is wider than the single statement suggests. Detection is on the
 * canonical form and the classified target, never Laravel's raw grammar.
 */
final class TruncateRule extends AbstractPgsqlSafetyRule implements ProvidesRemediation
{
    /** The considered `none` this rule produces, built once. */
    private readonly NoSafeSequenceTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new NoSafeSequenceTemplate;
    }

    public function id(): string
    {
        return 'PG.L1.TRUNCATE';
    }

    /**
     * A considered `none` — the first one in this package, and the case the value exists for.
     *
     * There is no safe standard sequence for a `TRUNCATE` in a migration, and that is not a gap in
     * the template library. Every honest answer is a decision about somebody's data: is it
     * reference data being reloaded, a table being retired, a test fixture in the wrong file? Those
     * lead to different actions, and a template that picked one would be answering a question it
     * cannot see.
     *
     * So the payload says exactly that, with the reason attached. `strategy: none` is a
     * CONCLUSION — "a rule looked at this and there is nothing standard to recommend" — which is a
     * different fact from an absent payload, and the one worth reporting here.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if (! $statement->is(StatementKind::TruncateTable)) {
            return null;
        }

        return $this->template->payload(
            'sqlens::messages.remediation.no_safe_sequence.truncate',
            'sqlens::messages.remediation.no_safe_sequence.verification',
            $this->id(),
            $this->downtimeClass(),
        );
    }

    public function level(): Level
    {
        return Level::Destructive;
    }

    /**
     * Online: the ACCESS EXCLUSIVE lock is real but momentary — TRUNCATE does not scan
     * or rewrite. The danger is the irreversible data loss, which is the LEVEL, kept
     * separate from the deploy-time impact this axis models.
     */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $statement->is(StatementKind::TruncateTable)) {
            return null;
        }

        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget && $statement->migration->createsTable($table->qualifiedName())) {
            return null;
        }

        $cascade = preg_match('/\bCASCADE\b/', $statement->canonical) === 1
            ? ' It uses CASCADE, so every table with a foreign key to this one is truncated with it.'
            : '';

        return 'TRUNCATE in up() empties the table with no confirmation and no way back once the deploy '
            .'is past, and it takes an ACCESS EXCLUSIVE lock that blocks all access to the table while it '
            .'runs.'.$cascade.' If the loss is intended, annotate the migration with #[SqlensAllowDestructive] '
            .'and a reason.';
    }
}
