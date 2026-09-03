<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L4;

use Override;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Pgsql\PgTypeChangeMatrix;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\Support\ColumnTypeChange;
use Pushery\SQLens\Findings\Confidence;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\ExpandContractTemplate;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Narrowing a column's type — `bigint → integer`, `double precision → real` — can
 * truncate values that no longer fit and breaks any running old application version that
 * still writes the wider range. Level 2 asks whether the change LOCKS the table (a
 * rewrite); this level asks whether it is BACKWARD-INCOMPATIBLE, a separate axis, and the
 * two may both fire on the one statement without repeating each other.
 *
 * The honest hard part is the same as the rewrite rule's: the migration names only the
 * TARGET type, not the source. So this reads the target-keyed matrix
 * ({@see PgTypeChangeMatrix::isNarrowing()}) and is `heuristic` — it flags a target whose
 * dominant real case is a narrowing (`integer`, `smallint`, `real`, whose one common
 * source is a wider sibling) and names the source-check as the thing to confirm.
 *
 * What it deliberately does NOT do: guess at a PARAMETRIZED narrowing. `varchar(255) →
 * varchar(50)` and `varchar(50) → varchar(255)` are the same target to a static reader —
 * the length that settles it is not in the SQL — so this rule stays silent on
 * `varchar`/`numeric` rather than fire on half the widenings too. That is not a silent
 * green: such a change already surfaces as an `undetermined` on the rewrite axis
 * (`PG.L2.TYPE_CHANGE_REWRITE`), so the statement is never passed off as clean. A
 * parametrized narrowing is a documented limit of an SQL-only tool, not a claim of safety.
 *
 * Silent, too, when the column is on a table this migration just created (no old version
 * ever saw the wider type). Detection is on the canonical form; type aliases (`int4`,
 * `float4`) fold to their canonical spelling in the matrix, never string-compared.
 */
final class TypeNarrowingRule extends AbstractPgsqlSafetyRule implements ProvidesRemediation
{
    private readonly PgTypeChangeMatrix $matrix;

    /** The neutral sequence this rule hands over, built once. */
    private readonly ExpandContractTemplate $template;

    public function __construct(string $projectRoot, ?PgTypeChangeMatrix $matrix = null)
    {
        parent::__construct($projectRoot);

        $this->matrix = $matrix ?? PgTypeChangeMatrix::bundled();
        $this->template = new ExpandContractTemplate;
    }

    /**
     * The four-phase sequence, filled with the one fact a narrowing statement actually carries.
     *
     * The table is fillable; the NEW column's name and type are not, because they do not exist yet
     * — they are decisions somebody makes, and inventing them would be inventing a schema. The old
     * column comes from {@see ColumnTypeChange}, the same reading {@see judge()} uses, so the
     * material can never name a different column than the finding does.
     *
     * The template itself is driver-neutral: expand/contract is `ADD COLUMN` and `DROP COLUMN` on
     * both engines, and an architecture test holds it to importing no driver.
     *
     * It asks the same matrix {@see judge()} asks, and that is not belt-and-braces. A WIDENING is a
     * different operation, not a milder one: nothing that read the narrower type stops working, so
     * there is nothing to stage. A four-phase plan handed over for `integer → bigint` would be a
     * work order attached to a change that costs nothing — more expensive than saying nothing, which
     * is what this level's guardrail against cargo-cult advice means.
     *
     * What it does NOT re-ask is whether the finding MATTERS — the table born in this migration is
     * {@see judge()}'s business. That gate decides whether anybody needs the plan; this one decides
     * whether the plan describes the statement at all, and only the second is a property of the
     * material.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        $change = ColumnTypeChange::of($statement);

        if (! $change instanceof ColumnTypeChange || ! $this->matrix->isNarrowing($change->targetType())) {
            return null;
        }

        $context = ['old_column' => $change->column];

        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget) {
            $context['table'] = $table->qualifiedName();
        }

        // The citation is resolved INSIDE the template, from this rule's id. It cannot be resolved
        // here: a rule class must not name the evidence register at all, because a verdict that
        // consulted a citation would be deciding safety from a link.
        return $this->template->payload($context, $this->id(), $this->downtimeClass());
    }

    public function id(): string
    {
        return 'PG.L4.TYPE_NARROWING';
    }

    public function level(): Level
    {
        return Level::BackwardCompatibility;
    }

    /** Online: the compatibility break is the level; the lock/rewrite is PG.L2.TYPE_CHANGE_REWRITE's axis. */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    /** Heuristic: the target is usually decisive, but the source type that settles it is not in the SQL. */
    #[Override]
    public function confidence(): Confidence
    {
        return Confidence::Heuristic;
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        // ALTER COLUMN <col> TYPE <target>, read ONCE — by the same object the remediation reads,
        // so the finding and its fix material can never disagree about which column this is.
        $change = ColumnTypeChange::of($statement);

        if (! $change instanceof ColumnTypeChange) {
            return null;
        }

        // A change on a column of a table born in this migration breaks no old version.
        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget && $statement->migration->createsTable($table->qualifiedName())) {
            return null;
        }

        if (! $this->matrix->isNarrowing($change->targetType())) {
            return null;
        }

        return 'This changes the column to a narrower type, which truncates any value that no longer '
            .'fits and breaks a running old application version that still writes the wider range. Add '
            .'the narrower column alongside, backfill and switch reads/writes across a deploy, then drop '
            .'the old one — never narrow in place under live traffic. SQLens sees only the target type, '
            .'not the source, so confirm the current column type before deploying; this is the '
            .'compatibility axis, separate from the rewrite lock (PG.L2.TYPE_CHANGE_REWRITE).';
    }
}
