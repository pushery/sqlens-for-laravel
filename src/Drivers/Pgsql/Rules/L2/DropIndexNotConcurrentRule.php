<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L2;

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
 * The other side of the same coin as `PG.L2.INDEX_NOT_CONCURRENT`: `DROP INDEX`
 * without `CONCURRENTLY` takes an ACCESS EXCLUSIVE lock on the index's table, which
 * conflicts with every other lock and so blocks reads and writes to the table for as
 * long as the drop holds it. `DROP INDEX CONCURRENTLY` releases without that block —
 * at the cost of running outside a transaction and dropping exactly one index per
 * statement, which the finding names.
 *
 * A DROP INDEX names only the index, never its table, so this rule cannot apply the
 * "table created or dropped in the same migration" carve-out the create-index rule
 * has — the statement does not carry the table to check. That is a documented limit,
 * not a silent gap: dropping an index in the same migration that drops its table is
 * unusual (DROP TABLE removes the index for you), so the residual false-positive
 * surface is small, and a real one is accepted with `#[SqlensIgnore]`.
 *
 * Detection is on the canonical form, never Laravel's raw grammar.
 */
final class DropIndexNotConcurrentRule extends AbstractPgsqlSafetyRule implements ProvidesRemediation
{
    /**
     * The one template this rule hands out, built once.
     *
     * Not built per finding, and the reason is measurable rather than stylistic: the template reads
     * the shipped evidence register to fill its references, and that read costs about 0.4 ms — free
     * once per run, and a bill that grows with the number of flagged migrations if it is paid per
     * finding. Held the same way {@see RuleDriverNotes} is on the base: resolved in the constructor,
     * immutable afterwards, so nothing about a verdict can depend on how often it was asked.
     */
    private readonly ConcurrentlyTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new ConcurrentlyTemplate;
    }

    public function id(): string
    {
        return 'PG.L2.DROP_INDEX_NOT_CONCURRENT';
    }

    /**
     * The safe sequence — the drop side of the same template, which is a different sequence.
     *
     * A `DROP INDEX` names no table and no columns, so the material it produces is shorter than the
     * create side's by exactly the facts the statement does not carry. That is the template's job,
     * not this rule's: the rule contributes only its id and its deploy impact, both read from what
     * it already declares, so the finding and its fix material cannot disagree.
     *
     * Narrowed to a non-null return, the same as the build side: the sequence exists for every
     * finding this rule emits, so an optional return would describe a state that never occurs.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        // One reading, shared with the judgment below. Off this shape the template would name an
        // index the statement does not drop.
        if (! $this->describesDropIndex($statement)) {
            return null;
        }

        return $this->template->forDropIndex($statement, $this->id(), $this->downtimeClass());
    }

    /** Whether this statement is the shape both the judgment and the fix material are about. */
    private function describesDropIndex(MigrationStatementView $statement): bool
    {
        return $statement->is(StatementKind::DropIndex);
    }

    public function level(): Level
    {
        return Level::BlockingDdl;
    }

    /** Blocking: the ACCESS EXCLUSIVE lock on the table degrades a live table without rewriting it. */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Blocking;
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $this->describesDropIndex($statement)) {
            return null;
        }

        if (preg_match('/\bCONCURRENTLY\b/', $statement->canonical) === 1) {
            return null;
        }

        return 'DROP INDEX without CONCURRENTLY takes an ACCESS EXCLUSIVE lock on the index\'s table, '
            .'blocking reads and writes to it until the drop completes — an outage on a large, live '
            .'table. Use DROP INDEX CONCURRENTLY, which releases without that block; note it cannot run '
            .'inside a transaction and drops only one index per statement.';
    }
}
