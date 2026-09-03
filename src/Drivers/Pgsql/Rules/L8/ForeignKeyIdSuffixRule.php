<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L8;

use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Canonical\TargetRole;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Contracts\JudgesMigrationStatements;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Convention\ForeignKeyIdSuffix;
use Pushery\SQLens\Rules\Convention\NamingConvention;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A single-column foreign key whose column does not end in the configured suffix.
 *
 * ## Why a naming convention is worth a rule here
 *
 * Laravel resolves a relation by DERIVING the foreign key's name from the related model — `user_id`
 * for a `User`. A column that departs from it is legal and keeps working, at the price of every
 * relation on that side having to name it explicitly, forever, in code nobody thinks to re-check
 * when the schema changes. That is what this rule names: not a defect, a standing tax.
 *
 * ## The FK-ness comes from the constraint, never from the name
 *
 * Both paths read the schema — see {@see ForeignKeyIdSuffix}, which sets out why a rule that
 * inferred "this column carries a relation" from `_id` would find only the columns that already
 * satisfy it, and would pass on every schema including the ones it was written for.
 *
 * On PostgreSQL the constraint is what the catalog reports and what the canonical statement
 * kind names, so neither half of this rule can be satisfied by a well-chosen name.
 */
final class ForeignKeyIdSuffixRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes, JudgesMigrationStatements
{
    /**
     * @param  NamingConvention  $naming  the convention a project asked for, built once by the
     *                                    registry and handed down — a rule that read the
     *                                    configuration would have a verdict its own tests cannot see
     */
    private readonly NamingConvention $naming;

    public function __construct(string $projectRoot = '', ?NamingConvention $naming = null)
    {
        parent::__construct($projectRoot);

        $this->naming = $naming ?? NamingConvention::shipped();
    }

    /** @return non-empty-list<SchemaObjectType> */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Table];
    }

    public function id(): string
    {
        return 'PG.L8.FK_ID_SUFFIX';
    }

    public function level(): Level
    {
        return Level::Conventions;
    }

    public function category(): Category
    {
        return Category::Convention;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Lint, Suite::Audit];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Table) {
            return [];
        }

        $offenders = [];

        foreach (ForeignKeyIdSuffix::keysOf($object) as $constraint => $columns) {
            if (! ForeignKeyIdSuffix::judges($columns)) {
                continue;
            }

            $column = ForeignKeyIdSuffix::bareName($columns[0]);

            if ($this->naming->exempts($column) || ! ForeignKeyIdSuffix::violates($column, $this->naming->foreignKeySuffix)) {
                continue;
            }

            $offenders[$column] = $constraint;
        }

        if ($offenders === []) {
            return [];
        }

        // One verdict for the table, naming every offending column on it. Speaking once per object
        // is this repository's convention for a catalog rule and is held by an architecture test; a
        // finding per column would report the same table repeatedly and bury the one that matters.
        ksort($offenders);

        $named = [];

        foreach ($offenders as $column => $constraint) {
            $named[] = $this->sentence($column, (string) $constraint);
        }

        return [RuleVerdict::flag(implode(' ', $named), $object->qualifiedName, $object->type)];
    }

    public function judgeStatement(MigrationStatementView $statement): ?RuleVerdict
    {
        // A REFERENCED target is what makes this a foreign key, and the statement KIND is not.
        //
        // ⚠️ Measured, because the obvious predicate is wrong on one of the two engines: MySQL's
        // canonicalization classifies `ALTER TABLE … ADD CONSTRAINT … REFERENCES …` as
        // `add_foreign_key`, and PostgreSQL's classifies the SAME statement as `add_constraint` —
        // it has no `AddForeignKey` signature at all. A rule gated on the kind would therefore work
        // on MySQL and be dead on PostgreSQL, with nothing red to say so: no finding is exactly what
        // a schema whose keys are all named correctly produces.
        //
        // Both engines DO mark the referenced table with `TargetRole::Referenced`, and only a
        // foreign key has one — `UNIQUE` and `PRIMARY KEY` carry a column list and no reference. So
        // the discriminator is read from the parse on both sides, and it still cannot be satisfied
        // by a name.
        $references = array_any(
            $statement->targets,
            static fn (StatementTarget $target): bool => $target->role === TargetRole::Referenced,
        );

        if (! $references) {
            return null;
        }

        if (! ForeignKeyIdSuffix::judges($statement->keyColumns)) {
            return null;
        }

        $column = ForeignKeyIdSuffix::bareName($statement->keyColumns[0]);

        if ($this->naming->exempts($column) || ! ForeignKeyIdSuffix::violates($column, $this->naming->foreignKeySuffix)) {
            return null;
        }

        // …and only where the intended name is DERIVABLE from the referenced table. See
        // {@see ForeignKeyIdSuffix::derivesFrom()} — a foreign key onto a natural key is named after
        // the column it holds, and reporting it would be reporting a correct schema.
        $referenced = null;

        foreach ($statement->targets as $target) {
            if ($target->role === TargetRole::Referenced) {
                $referenced = $target->qualifiedName();
            }
        }

        if ($referenced === null || ! ForeignKeyIdSuffix::derivesFrom($column, $referenced)) {
            return null;
        }

        return RuleVerdict::flag($this->sentence($column, null));
    }

    private function sentence(string $column, ?string $constraint): string
    {
        return 'The foreign key column `'.$column.'`'
            .($constraint === null ? '' : ' (constraint `'.$constraint.'`)')
            .' does not end in `'.$this->naming->foreignKeySuffix.'`, so Laravel cannot derive the'
            .' relation from it and every relation on this side has to name the column explicitly.'
            .' What identifies it as a foreign key here is the constraint — the name was never consulted.';
    }
}
