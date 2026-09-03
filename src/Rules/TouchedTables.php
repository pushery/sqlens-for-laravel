<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The TABLES a migration statement names, and whether the migration creates every one of them.
 *
 * ## Why this is shared rather than a private method in each rule
 *
 * Two rules ask the identical question for opposite reasons. {@see Drivers\Pgsql\Rules\L2\ConstraintNotValidatedRule}
 * asks what MATTERS: a constraint added to a table born in this migration locks nothing anyone can
 * observe — but a foreign key from a new table to a LIVE one still locks the live one, which is the
 * documented outage the rule exists for, so the exception only holds when every table is new.
 * {@see Drivers\Pgsql\Rules\L5\ForeignKeyWithoutIndexRule} asks what can be KNOWN: only a migration
 * that creates the table carries that table's index history, and a foreign key names two tables of
 * which either could be the one carrying the key.
 *
 * They arrived at the same predicate independently, and for a while each carried its own
 * byte-identical copy of it. That is the shape of a defect waiting to happen: the predicate decides
 * whether a rule may speak AT ALL, so two copies drifting apart would not read as a bug in a helper
 * — it would read as one rule being right and the other being mysteriously silent. One reading,
 * one place, exactly as {@see MigrationVerdicts} exists so two bases cannot build differently
 * shaped findings.
 */
final readonly class TouchedTables
{
    /**
     * The table targets this statement names, in the classifier's deterministic order.
     *
     * Read from the CLASSIFICATION, never from the SQL: a statement's tables are resolved
     * identifiers, so this cannot drift on quoting or letter case the way a text scan would.
     *
     * @return list<StatementTarget>
     */
    public static function of(MigrationStatementView $statement): array
    {
        return array_values(array_filter(
            $statement->targets,
            static fn (StatementTarget $target): bool => $target->type === SchemaObjectType::Table,
        ));
    }

    /**
     * Whether every table this statement names is born in this migration.
     *
     * A statement with no table target at all answers false — an unclassified statement is not one
     * whose tables were all created here, it is one nobody could name, and answering "all of them"
     * over an empty set would be vacuously true for exactly the statements a rule cannot place.
     */
    public static function allCreatedHere(MigrationStatementView $statement): bool
    {
        $tables = self::of($statement);

        if ($tables === []) {
            return false;
        }

        return array_all(
            $tables,
            static fn (StatementTarget $table): bool => $statement->migration->createsTable($table->qualifiedName()),
        );
    }
}
