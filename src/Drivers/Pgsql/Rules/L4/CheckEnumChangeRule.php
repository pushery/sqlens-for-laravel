<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L4;

use Override;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Pgsql\Remediation\NotValidThenValidateTemplate;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L2\ConstraintShape;
use Pushery\SQLens\Findings\Confidence;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Laravel's `$table->enum()` does NOT create a PostgreSQL enum type — it makes a
 * `varchar` column with a `CHECK (col IN (…))` constraint. So changing the allowed
 * values is not an `ALTER TYPE` at all: it is a DROP of the old CHECK and an ADD of a
 * new one, and the ADD validates the whole table under a lock. This confusion is the
 * commonest enum trap in Laravel projects, and it needs its own rule with its own
 * remedy — nothing about it looks like `ALTER TYPE … ADD VALUE`.
 *
 * The rule fires on the `ADD CONSTRAINT … CHECK (col IN (…))` when the same migration
 * also DROPS a constraint — that drop is what distinguishes a CHANGE (Laravel's
 * enum() change: drop then add) from a first-time enum column (an add alone), which is
 * correctly silent. It is heuristic: recognizing the enum-change shape, and the
 * compatibility half depending on application code the tool cannot see.
 *
 * Two things the finding names, kept apart from `PG.L2.CONSTRAINT_NOT_VALIDATED` (which
 * also fires on the same ADD, on the availability axis — both are allowed, the texts do
 * not repeat): the validating scan under lock (its remedy is the NOT VALID pattern), and
 * that removing an allowed value breaks any running old app version that still writes it.
 *
 * Silent when the table is created in this same migration (a fresh column has no rows to
 * validate and no old app version to break). Detection is on the canonical form — never
 * Laravel's raw grammar, the temptation is greatest exactly here where the pattern comes
 * from that grammar.
 */
final class CheckEnumChangeRule extends AbstractPgsqlSafetyRule implements ProvidesRemediation
{
    /** The constraint sequence this rule points at — referenced, never copied. */
    private readonly NotValidThenValidateTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new NotValidThenValidateTemplate;
    }

    public function id(): string
    {
        return 'PG.L4.CHECK_ENUM_CHANGE';
    }

    /**
     * The `NOT VALID` → `VALIDATE` sequence, because this "enum change" is a CHECK constraint.
     *
     * Laravel's `$table->enum()` makes no enum type at all — it is a varchar with a
     * `CHECK (col IN (…))` — so the remedy has nothing to do with `ALTER TYPE`. It is the same
     * constraint sequence its level-2 sibling hands over for the same statement, on the other axis,
     * and pointing at that template rather than writing an enum-flavored copy is what keeps one
     * statement from carrying two versions of one plan.
     *
     * A CHECK is `NOT VALID`-capable, which is the shape this passes — and the only reason it can
     * name the shape without asking {@see ConstraintShape} is that the statement has already been
     * established to be an `ADD CONSTRAINT … CHECK`. That establishing happens HERE, in
     * {@see addsAnEnumCheck()}, not only in {@see judge()}: the sentence used to be true of the rule
     * and false of this method, which is the shape of a precondition that holds until the day a
     * second caller arrives. Passing `NotValidCapable` for a statement that carries no constraint at
     * all would name a shape nobody read.
     *
     * It does not re-ask whether the finding MATTERS. The fresh-table and the paired-DROP gates are
     * {@see judge()}'s: they decide whether this rule has anything to say, while the sequence itself
     * stays correct for any populated table's CHECK — which is why its level-2 sibling hands over
     * the same one.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if (! $this->addsAnEnumCheck($statement)) {
            return null;
        }

        return $this->template->forConstraint(
            $statement,
            ConstraintShape::NotValidCapable,
            $this->id(),
            $this->downtimeClass(),
        );
    }

    public function level(): Level
    {
        return Level::BackwardCompatibility;
    }

    /** Online here: the compatibility break is the level; the lock is PG.L2.CONSTRAINT_NOT_VALIDATED's axis. */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    /** Heuristic: recognizing the enum-change shape, and the break depends on unseen app code. */
    #[Override]
    public function confidence(): Confidence
    {
        return Confidence::Heuristic;
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $this->addsAnEnumCheck($statement)) {
            return null;
        }

        // A fresh table's column has no rows to validate and no old version to break.
        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget && $statement->migration->createsTable($table->qualifiedName())) {
            return null;
        }

        // No drop in the migration → this is a first-time enum column, not a change.
        if (! $statement->migration->dropsAConstraint) {
            return null;
        }

        return 'This looks like changing a Laravel enum() column: it is a varchar with a CHECK '
            .'constraint, so the change drops the old CHECK and adds a new one, which validates the '
            .'whole table under a lock — add it NOT VALID and VALIDATE it separately (see '
            .'PG.L2.CONSTRAINT_NOT_VALIDATED). And removing an allowed value breaks any running old '
            .'application version that still writes it: add first, deploy the code, remove later. '
            .'SQLens reads only the SQL, so treat this as a prompt to check.';
    }

    /**
     * The `ADD CONSTRAINT … CHECK (col in (…))` shape — Laravel's `enum()` in PostgreSQL's spelling.
     *
     * Read once, for the verdict AND for the material, so the two can never disagree about whether
     * there is a constraint here at all. `IN` is lowercase in the canonical form; the match is on
     * that normalized form, never on Laravel's raw grammar — the temptation to reach for the grammar
     * is greatest exactly here, where the pattern comes from it.
     */
    private function addsAnEnumCheck(MigrationStatementView $statement): bool
    {
        return $statement->is(StatementKind::AddConstraint)
            && preg_match('/\bCHECK\s*\(.*\bin\b.*\)/i', $statement->canonical) === 1;
    }
}
