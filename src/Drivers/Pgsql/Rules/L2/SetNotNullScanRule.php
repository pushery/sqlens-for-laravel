<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L2;

use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Pgsql\Remediation\NotValidThenValidateTemplate;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
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
 * Since PostgreSQL 12 the scan can be avoided: add a `CHECK (col IS NOT NULL)`
 * constraint first (NOT VALID, then VALIDATE CONSTRAINT under a weaker lock), and the
 * later `SET NOT NULL` trusts the validated check and skips the full scan. The finding
 * names that cheaper path.
 *
 * Two exceptions, both silent:
 *
 *  - **The column is on a table this migration created.** A fresh table holds no rows,
 *    so the scan is free — this is the version trap the rule must not fall into (it is
 *    NOT the same as `ADD COLUMN … NOT NULL DEFAULT`, which is a different statement the
 *    rule never matches).
 *  - **The migration adds a `CHECK (col IS NOT NULL)` for the same column.** A user who
 *    wrote that check is applying the safe pattern deliberately; flagging their
 *    migration would be crying wolf on the exact good behavior the rule recommends.
 *    This is detected within the SAME migration; a check added in an earlier migration
 *    is not visible here (cross-migration state is not carried), a documented limit that
 *    the `#[SqlensIgnore]` annotation covers.
 *
 * Detection is on the canonical form — no rewrite claim, because `SET NOT NULL` scans
 * but does NOT rewrite the table — never Laravel's raw grammar.
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
     * The sequence that makes the scan unnecessary — the same NOT VALID trick in front of a third
     * statement.
     *
     * Since PostgreSQL 12, `SET NOT NULL` will TRUST a validated `CHECK (col IS NOT NULL)` and skip
     * reading every row. So this hands over the constraint template's own sequence rather than an
     * enum-flavored copy of it: one place keeps the `NOT VALID` reasoning, and the column comes
     * from the SAME reading {@see judge()} uses.
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
        // ALTER COLUMN <col> set NOT NULL, read by the ONE reader of that clause — the same one the
        // remediation uses, so the material can never name a different column than the finding.
        $change = SetNotNullChange::of($statement);

        if (! $change instanceof SetNotNullChange) {
            return null;
        }

        $column = $change->column;

        // A fresh table holds no rows to scan. The altered table is the classified
        // target, not a name re-parsed from the SQL.
        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget && $statement->migration->createsTable($table->qualifiedName())) {
            return null;
        }

        // The safe pattern is present for this column — the user is doing it right.
        if ($statement->migration->hasNotNullCheckFor($column)) {
            return null;
        }

        return 'SET NOT NULL scans the whole table to prove no row is null, under an ACCESS EXCLUSIVE '
            .'lock — an outage on a large, live table. Add a CHECK (col IS NOT NULL) constraint first '
            .'(NOT VALID, then VALIDATE CONSTRAINT under a weaker lock), and the later SET NOT NULL '
            .'trusts it and skips the scan. It does not rewrite the table, only scans it.';
    }
}
