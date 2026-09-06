<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L2;

use Override;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Deploy\Contracts\DeclaresOperationClass;
use Pushery\SQLens\Drivers\Pgsql\PgTypeChangeMatrix;
use Pushery\SQLens\Drivers\Pgsql\Remediation\RewriteAvoidanceTemplate;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\Support\ColumnTypeChange;
use Pushery\SQLens\Drivers\Pgsql\TypeChangeImpact;
use Pushery\SQLens\Findings\Confidence;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * An `ALTER COLUMN … TYPE` that PostgreSQL cannot make binary-coercibly rewrites the
 * whole table under an ACCESS EXCLUSIVE lock — for the duration of a full pass over
 * every row. What is instant on a laptop is an outage on a large, live table.
 *
 * The honest hard part: the migration SQL names only the TARGET type, never the source,
 * so a static rule cannot know for certain whether a given change rewrites. This rule
 * therefore reads a matrix keyed on the target ({@see PgTypeChangeMatrix}) and declares
 * itself HEURISTIC — a target it knows rewrites is flagged, a target it knows is free
 * (varchar → text) is silent, and a target it does not classify is UNDETERMINED with a
 * named reason, never a silent pass. A `USING` clause forces a rewrite unconditionally,
 * and that is decided here rather than from the matrix.
 *
 * Three-valued, so it overrides {@see verdict()} rather than {@see judge()}: a rule that
 * can honestly answer "I don't know" must be able to say so.
 *
 * The same-migration exception applies when the whole TABLE is created here (its column
 * holds no data to rewrite). A column ADDED then retyped within one migration on a
 * pre-existing table is not caught — the classifier does not model per-column additions —
 * a documented limit, as for the other column rules.
 *
 * This is the availability question (does it lock the table). Whether the new type is a
 * NARROWING that can break a running app is the compatibility question and belongs to
 * the separate level-4 rule; this finding does not repeat that.
 */
final class TypeChangeRewriteRule extends AbstractPgsqlSafetyRule implements DeclaresOperationClass, ProvidesRemediation
{
    private readonly PgTypeChangeMatrix $matrix;

    /** The staged retyping this rule hands over, built once — it resolves the citation itself. */
    private readonly RewriteAvoidanceTemplate $template;

    public function __construct(string $projectRoot, ?PgTypeChangeMatrix $matrix = null)
    {
        parent::__construct($projectRoot);

        $this->matrix = $matrix ?? PgTypeChangeMatrix::bundled();
        $this->template = new RewriteAvoidanceTemplate;
    }

    public function id(): string
    {
        return 'PG.L2.TYPE_CHANGE_REWRITE';
    }

    /**
     * A `USING` retype copies every row of the table into a new heap under ACCESS EXCLUSIVE, so what
     * it costs is BYTES rather than rows — a narrow billion-row table can rewrite faster than a wide
     * ten-million-row one.
     */
    public function operationClass(): string
    {
        return 'rewrite';
    }

    /**
     * The staged retyping — and NOT for every statement this rule looks at.
     *
     * The version-awareness the ticket makes mandatory, expressed as an absence. A change the
     * matrix classifies as metadata-only produces no finding and gets no plan; and a change the
     * matrix cannot classify — the source type is not in the statement — gets none either, because
     * that finding is a QUESTION rather than a verdict. Handing over a six-step migration plan for
     * a change that may well be free is a false positive with a work order attached, which is more
     * expensive than saying nothing.
     *
     * So a payload exists exactly where a rewrite is established: a `USING` expression, which forces
     * one whatever the types are, or a target the matrix knows rewrites.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        $change = ColumnTypeChange::of($statement);

        if (! $change instanceof ColumnTypeChange) {
            return null;
        }

        $rewrites = $change->hasUsingClause()
            || $this->matrix->classify($change->targetType()) === TypeChangeImpact::Rewrite;

        if (! $rewrites) {
            return null;
        }

        $context = ['old_column' => $change->column];

        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget) {
            $context['table'] = $table->qualifiedName();
        }

        return $this->template->payload($context, $this->id(), $this->downtimeClass());
    }

    public function level(): Level
    {
        return Level::BlockingDdl;
    }

    /** A rewrite holds the table under ACCESS EXCLUSIVE for a full pass — blocking. */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Blocking;
    }

    /**
     * Heuristic, and this is the rule the confidence axis exists for: the target type is
     * a pattern that is usually decisive, but the source type — which settles it for
     * certain — is not in the migration. A reader must see that the verdict carries a
     * margin, not read it as proof.
     */
    #[Override]
    public function confidence(): Confidence
    {
        return Confidence::Heuristic;
    }

    #[Override]
    protected function verdict(MigrationStatementView $statement): ?RuleVerdict
    {
        // ALTER COLUMN <col> TYPE <target…>, read by the ONE reader of that clause. A SET NOT NULL
        // or SET DEFAULT alter has no TYPE and is left to its own rule.
        $change = ColumnTypeChange::of($statement);

        if (! $change instanceof ColumnTypeChange) {
            return null;
        }

        // A change to a column of a table born in this migration rewrites nothing live.
        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget && $statement->migration->createsTable($table->qualifiedName())) {
            return null;
        }

        if ($change->hasUsingClause()) {
            return RuleVerdict::flag(
                'ALTER COLUMN … TYPE with a USING clause rewrites the whole table under an ACCESS '
                .'EXCLUSIVE lock, for a full pass over every row — an outage on a large, live table. '
                .'A USING expression forces the rewrite unconditionally.',
            );
        }

        // `targetType()`, not `rest`. Both call sites in this rule used to pass the whole tail, and
        // `rest` is documented as the type PLUS a trailing `USING` — which reads as the right choice
        // for the rewrite question until you notice that `hasUsingClause()` has already answered it,
        // three lines up and again above, before either call is reached. So the tail bought nothing
        // and cost the compound case: `ALTER TABLE t ALTER COLUMN c TYPE BIGINT, ALTER COLUMN c SET
        // NOT NULL, …` is one statement, and the matrix was handed all of it. It classifies nothing
        // of the sort, so the rule answered `undetermined` — over a bigint widening, which is the
        // clearest rewrite there is.
        //
        // That shape is not exotic. It is what Laravel's `->change()` compiles to, every time: the
        // builder restates every modifier, so one column change is one compound statement. The
        // sibling rule PG.L4.TYPE_NARROWING reads `targetType()` at both of ITS call sites and was
        // right all along — two rules over one parse, and only one of them used the projection the
        // parse offers. Exactly the drift `ColumnTypeChange` was written to make impossible, arrived
        // at from inside it.
        return match ($this->matrix->classify($change->targetType())) {
            TypeChangeImpact::Rewrite => RuleVerdict::flag(
                'ALTER COLUMN … TYPE to this type rewrites the whole table under an ACCESS EXCLUSIVE '
                .'lock, for a full pass over every row — an outage on a large, live table. If the '
                .'change is unavoidable, take a maintenance window or stage it through a new column.',
            ),
            TypeChangeImpact::MetadataOnly => null,
            TypeChangeImpact::Unknown => RuleVerdict::undetermined(
                'ALTER COLUMN … TYPE targets a type SQLens cannot classify from the migration alone — '
                .'the source type is not in the statement — so whether it rewrites the table is unknown. '
                .'Verify against the target column\'s current type before deploying.',
                UndeterminedReason::UnclassifiedTypeChange,
            ),
        };
    }
}
