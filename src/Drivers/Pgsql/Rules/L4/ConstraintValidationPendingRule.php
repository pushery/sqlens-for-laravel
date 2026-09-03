<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L4;

use Override;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Deploy\Contracts\ProducesDebt;
use Pushery\SQLens\Drivers\Pgsql\Deploy\NotValidConstraintCheck;
use Pushery\SQLens\Drivers\Pgsql\Remediation\NotValidThenValidateTemplate;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L2\ConstraintNotValidatedRule;
use Pushery\SQLens\Findings\Confidence;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Subjects\MigrationContext;
use Pushery\SQLens\Subjects\MigrationStatementDigest;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The safe half of the safe pattern, with the other half nowhere in the run.
 *
 * `ADD CONSTRAINT … NOT VALID` is the RIGHT thing to do — it is what
 * {@see ConstraintNotValidatedRule} recommends, and that
 * rule stays deliberately silent about it. The constraint applies to every new row from the moment
 * it lands and costs a brief metadata lock instead of a full-table scan.
 *
 * It is also only half finished. Until `VALIDATE CONSTRAINT` runs, the constraint does not hold for
 * the rows that were already there, and the planner may not rely on it. Nothing breaks, nothing is
 * slow, and no error is raised — which is exactly why the second half is the one that gets
 * forgotten. This rule is the account of those open ends.
 *
 * ## Why this is not a complaint
 *
 * A finding here does not say the migration is wrong. It says a deliberate two-step is at step one,
 * and names which constraint is waiting. The level is what carries that: level 4 is backward
 * compatibility, the axis on which an unvalidated constraint really is a gap, and the security
 * severity stays absent because there is no security question here at all. What makes a specific
 * open end urgent is its AGE, and age is not a property of a migration — it is what the debt ledger
 * adds later.
 *
 * ## Why it reads the whole RUN, not this file
 *
 * `VALIDATE CONSTRAINT` belongs in a LATER migration; that separation IS the safe pattern. A rule
 * that read only its own file would report every correctly split pair as an open end — the finding
 * would sit on a file the reader is not allowed to edit, and its advice would be to add what has
 * already been added. So the question is asked of {@see MigrationContext::$runStatements},
 * the run-wide view that exists to WITHHOLD a finding the run as a whole disproves.
 *
 * On the single-file fast path the run is a SLICE, so a `VALIDATE` in another file is invisible and
 * this reports an open end that is already closed. That is the same direction of error the fast
 * path carries everywhere: it sees what it was given. It is also why the confidence is heuristic
 * rather than certain.
 *
 * ## Why the VALIDATE is read structurally
 *
 * `ALTER TABLE … VALIDATE CONSTRAINT <k>` is the one shape that classifies as `AlterTable` WITH a
 * constraint target — `ADD` and `DROP CONSTRAINT` each carry their own kind. The deploy-side check
 * {@see NotValidConstraintCheck} reads the same signature the
 * same way, which is what keeps the migration view and the catalog view from disagreeing about the
 * same constraint. Text matching on the canonical SQL would be a second reading of one fact.
 */
final class ConstraintValidationPendingRule extends AbstractPgsqlSafetyRule implements ProducesDebt, ProvidesRemediation
{
    /**
     * The word this debt is filed under, as a constant so nobody has to instantiate a rule to read
     * it.
     *
     * It became one when the remediation template for the level-2 rule needed to NAME the account
     * its own advice opens: `ADD CONSTRAINT … NOT VALID` is correct and incomplete at the same
     * moment, so the payload says which debt the reader is taking on until the second migration
     * lands. Reading it here rather than writing the string a second time is the whole point —
     * a third spelling would be a debt nobody could join to the entry it describes.
     */
    public const string DEBT_KIND = 'not_valid_constraint';

    /**
     * What kind of debt this rule's findings are, in the ledger.
     *
     * The SAME word the catalog side would use for the same thing. A migration that leaves a
     * constraint unvalidated and a catalog that reports one unvalidated are one debt seen from two
     * places, and a ledger that spelled them differently would carry both and reconcile neither.
     *
     * Stable and machine-facing: it is part of an entry's derived identity, so renaming it renames
     * every debt of this kind and restarts all their ages at zero.
     */
    public function debtKind(): string
    {
        return self::DEBT_KIND;
    }

    /**
     * The constraint this finding leaves behind, read from the finding's own object identity.
     *
     * Structural rather than parsed. The message names the constraint too, and reading it from
     * there would work today and break the first time somebody rewords a sentence — which is why
     * the registrar's contract forbids it and why the location learned to carry an object.
     *
     * Null for a finding of this rule is unreachable today (it only flags when it has a constraint
     * to name), and it stays nullable because that is the contract's answer for a finding that
     * carries no lasting state. A rule cannot promise on behalf of a future one.
     */
    public function debtReference(Finding $finding): ?string
    {
        return $finding->location->objectName;
    }

    /** The missing half, referenced from the constraint template rather than restated. */
    private readonly NotValidThenValidateTemplate $template;

    public function __construct(string $projectRoot)
    {
        parent::__construct($projectRoot);

        $this->template = new NotValidThenValidateTemplate;
    }

    public function id(): string
    {
        return 'PG.L4.CONSTRAINT_VALIDATION_PENDING';
    }

    public function level(): Level
    {
        return Level::BackwardCompatibility;
    }

    /** Online: adding NOT VALID is a brief metadata change, and the `VALIDATE` that follows takes a weaker lock. */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    /** Heuristic: on the single-file fast path a `VALIDATE` in another migration is out of view. */
    #[Override]
    public function confidence(): Confidence
    {
        return Confidence::Heuristic;
    }

    #[Override]
    /**
     * One statement, not three — because step one already happened.
     *
     * This rule is the account of a deliberate two-step sitting at step one, never a complaint about
     * it. `ADD CONSTRAINT … NOT VALID` was the right move. So the material is the half that is
     * missing, and handing over the whole sequence would tell somebody to add a constraint that is
     * already there, in a file they are not allowed to edit.
     *
     * The names come from the verdict's own reading, so the payload can never point at a different
     * constraint than the finding names.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        $verdict = $this->verdict($statement);

        if (! $verdict instanceof RuleVerdict || $verdict->isUndetermined() || $verdict->isPass) {
            return null;
        }

        $table = $statement->soleTarget(SchemaObjectType::Table);
        $constraint = $statement->soleTarget(SchemaObjectType::Constraint);

        $context = [];

        if ($table instanceof StatementTarget) {
            $context['table'] = $table->qualifiedName();
        }

        if ($constraint instanceof StatementTarget) {
            $context['constraint'] = $constraint->qualifiedName();
        }

        return $this->template->forPendingValidation($context, $this->id(), $this->downtimeClass());
    }

    #[Override]
    protected function verdict(MigrationStatementView $statement): ?RuleVerdict
    {
        if (! $statement->is(StatementKind::AddConstraint)) {
            return null;
        }

        // The safe form is the SUBJECT here, the exact inverse of the level-2 rule where it is the
        // exit. Read off the canonical form, where the keywords are normalized, never off Laravel's
        // raw grammar.
        if (! str_contains($statement->canonical, 'NOT VALID')) {
            return null;
        }

        $constraint = $statement->soleTarget(SchemaObjectType::Constraint);

        // No constraint name to account for. A debt this tool could not name is one it must not
        // record: an entry keyed on nothing would collide with every other one of its kind.
        if (! $constraint instanceof StatementTarget) {
            return null;
        }

        // The SUBJECT table, not the sole one. A `NOT VALID` constraint is in practice almost always
        // a foreign key — CHECK is rare, and PRIMARY KEY/UNIQUE do not support NOT VALID at all — so
        // the two-table shape is the COMMON case here, and `soleTarget()` answers null for it. The
        // constraint then kept its bare name while the catalog side wrote `public.…`, which is two
        // debts for one object, an account that doubles, and a reconciliation that never converges.
        $name = $this->qualifiedThroughTable($constraint, $statement->soleSubjectTarget(SchemaObjectType::Table));

        if ($this->validatedInThisRun($name, $statement->migration->runStatements)) {
            return null;
        }

        return RuleVerdict::flag(
            sprintf(
                'The constraint `%s` is added `NOT VALID` and nothing in this run validates it. That '
                .'first half is the right move — it applies to every new row immediately and takes a '
                .'brief metadata lock instead of scanning the table. The second half is what makes it '
                .'true of the rows that were already there: `ALTER TABLE … VALIDATE CONSTRAINT %s` in '
                .'a later migration, which scans under a SHARE UPDATE EXCLUSIVE lock that does not '
                .'block reads and writes. Until it runs, the constraint does not hold for existing '
                .'rows and the planner will not rely on it — silently, which is why this step is the '
                .'one that gets forgotten.',
                $name,
                $name,
            ),
            objectName: $name,
            objectType: SchemaObjectType::Constraint,
        );
    }

    /**
     * A constraint's name, qualified through the schema of the TABLE that holds it.
     *
     * A constraint is named WITHIN its table: `ALTER TABLE public.orders ADD CONSTRAINT foo …`
     * qualifies the table and never the constraint, so a rule reading only the constraint target
     * gets a bare name. The catalog side has `nspname` and writes `public.foo` — and two spellings
     * of one constraint are TWO debts, because an entry's identity hashes the object string. The
     * account would double silently and the reconciliation could never converge: each side would
     * want to remove the other's entry, forever.
     *
     * The table's schema is the honest source. It is present in the statement, it is the
     * qualification PostgreSQL itself applies, and using it invents nothing.
     *
     * **When the statement names no schema, neither does this.** `ALTER TABLE orders …` resolves
     * through `search_path`, which a static reader does not have. Guessing `public` would be right
     * most of the time and silently wrong for every project that uses a schema — and a wrong
     * identity is worse than a bare one, because it looks decided.
     */
    private function qualifiedThroughTable(StatementTarget $constraint, ?StatementTarget $table): string
    {
        $name = $constraint->qualifiedName();

        if (! $table instanceof StatementTarget || str_contains($name, '.')) {
            return $name;
        }

        $schema = $table->identifier->schema?->canonical;

        return $schema === null || $schema === '' ? $name : $schema.'.'.$name;
    }

    /** The table a captured statement addresses, or null when it names none. */
    private function tableTargetOf(MigrationStatementDigest $digest): ?StatementTarget
    {
        foreach ($digest->targets as $target) {
            if ($target->type === SchemaObjectType::Table) {
                return $target;
            }
        }

        return null;
    }

    /**
     * Whether any migration in this run validates the named constraint.
     *
     * Compared on the qualified name the classifier produced on both sides, so two spellings of one
     * constraint can never disagree — the canonicalization layer already folded quoting and casing
     * before either name reached this method.
     *
     * @param  list<MigrationStatementDigest>  $runStatements
     */
    private function validatedInThisRun(string $name, array $runStatements): bool
    {
        foreach ($runStatements as $digest) {
            if ($digest->kind !== StatementKind::AlterTable) {
                continue;
            }

            foreach ($digest->targets as $target) {
                if ($target->type !== SchemaObjectType::Constraint) {
                    continue;
                }

                // Qualified the SAME way as the constraint being judged, from that statement's own
                // table. Comparing a qualified name against a bare one would silence nothing and
                // report every correctly split pair — the exact false positive this method exists
                // to prevent.
                if ($this->qualifiedThroughTable($target, $this->tableTargetOf($digest)) === $name) {
                    return true;
                }
            }
        }

        return false;
    }
}
