<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L2;

use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Pgsql\Remediation\NotValidThenValidateTemplate;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\Support\NotNullCheckProof;
use Pushery\SQLens\Drivers\Pgsql\Rules\Support\SetNotNullChange;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * `ALTER TABLE … ALTER COLUMN … SET NOT NULL` scans the whole table to prove no
 * existing row holds a null, and it holds an ACCESS EXCLUSIVE lock for that scan. On a
 * large, live table that is an outage.
 *
 * On PostgreSQL 18 the scan moves under a weaker lock: the not-null constraint is added
 * `NOT VALID` and validated afterwards, and the validation reads the rows under SHARE
 * UPDATE EXCLUSIVE, which lets reads and writes go on. The finding names that path and the
 * remediation hands it over. The PostgreSQL 12 detour through a `CHECK (col IS NOT NULL)`
 * still works, and the second exception below still recognizes it.
 *
 * Two exceptions, both silent:
 *
 *  - **The column is on a table this migration created.** A fresh table holds no rows,
 *    so the scan is free — this is the version trap the rule must not fall into (it is
 *    not the same as `ADD COLUMN … NOT NULL DEFAULT`, which is a different statement the
 *    rule never matches).
 *  - **A valid `CHECK (col IS NOT NULL)` on the same column of the same table precedes the
 *    statement.** A user who wrote that check is applying the safe pattern deliberately;
 *    flagging their migration would be crying wolf on the exact good behavior the rule
 *    recommends. The check has to be one PostgreSQL trusts: added without `NOT VALID`, or
 *    validated by name after it, and before the `SET NOT NULL` ({@see NotNullCheckProof}). A
 *    check on another table, one never validated, or one that comes after proves nothing, and
 *    the table is scanned. This is detected within the same migration; a check added in an
 *    earlier migration is not visible here (cross-migration state is not carried), a
 *    documented limit that the `#[SqlensIgnore]` annotation covers.
 *
 * Detection is on the canonical form — no rewrite claim, because `SET NOT NULL` scans
 * but does not rewrite the table — never Laravel's raw grammar.
 */
final class SetNotNullScanRule extends AbstractPgsqlSafetyRule implements ProvidesRemediation
{
    /** The constraint sequence this rule hands over, built once. */
    private readonly NotValidThenValidateTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new NotValidThenValidateTemplate;
    }

    public function id(): string
    {
        return 'PG.L2.SET_NOT_NULL_SCAN';
    }

    /**
     * The sequence that moves the scan under a weaker lock: the not-null constraint added
     * `NOT VALID`, then validated.
     *
     * On 18 a not-null constraint accepts `NOT VALID` itself, so the PostgreSQL 12 detour through a
     * throwaway `CHECK` is not needed. This hands over the constraint template's own sequence
     * rather than a copy of it: one place keeps the `NOT VALID` reasoning, and the column comes
     * from the same reading {@see judge()} uses.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        $change = SetNotNullChange::of($statement);

        if (! $change instanceof SetNotNullChange) {
            return null;
        }

        $context = ['column' => $change->column];

        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget) {
            $context['table'] = $table->qualifiedName();
        }

        return $this->template->forSetNotNull($context, $this->id(), $this->downtimeClass());
    }

    public function level(): Level
    {
        return Level::BlockingDdl;
    }

    /** Blocking: the validating scan holds an ACCESS EXCLUSIVE lock, degrading a live table. */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Blocking;
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        // ALTER COLUMN <col> set NOT NULL, read by the one reader of that clause — the same one the
        // remediation uses, so the material can never name a different column than the finding.
        $change = SetNotNullChange::of($statement);

        if (! $change instanceof SetNotNullChange) {
            return null;
        }

        // A fresh table holds no rows to scan. The altered table is the classified
        // target, not a name re-parsed from the SQL.
        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget && $statement->migration->createsTable($table->qualifiedName())) {
            return null;
        }

        // The safe pattern is in place for this column of this table: a valid CHECK (col IS NOT NULL)
        // before this statement, which PostgreSQL trusts instead of scanning.
        if ($table instanceof StatementTarget && NotNullCheckProof::standsBefore($statement, $table, $change->name())) {
            return null;
        }

        return 'SET NOT NULL scans the whole table to prove no row is null, under an ACCESS EXCLUSIVE '
            .'lock — an outage on a large, live table. Add the not-null constraint NOT VALID instead '
            .'(ADD CONSTRAINT name NOT NULL col NOT VALID), then VALIDATE CONSTRAINT it in a later '
            .'migration, which reads the same rows under a weaker lock that lets reads and writes go on. '
            .'It does not rewrite the table, only scans it.';
    }
}
