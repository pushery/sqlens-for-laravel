<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\Support;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Subjects\MigrationStatementDigest;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The type a column has when a statement runs, as far as the statements the run executed before it
 * say.
 *
 * A migration names a column's type where it creates the column and where it changes it, and
 * nowhere else. So the type is known from the last earlier statement of the run that did either, as
 * long as every statement since can be followed. A CI run over every migration of a project starts
 * from an empty schema and sees each table created. What cannot be followed ends the reading with
 * the answer a migration read alone gives, not known: a rename, a statement nobody could classify, a
 * table of the same name under another qualification, a run that could not read one of its
 * migrations.
 *
 * A `--file` run reads only the files it was given. One file carries no history at all; several
 * files with a migration left out between them carry a history with a gap, and nothing in the run
 * marks it.
 */
final readonly class ColumnTypeBefore
{
    private function __construct(
        /** The type with the size it was written with, as the statement that gave it wrote it. */
        public string $type,
    ) {}

    /** The type the run gave the named column of the statement's table, or null when the run does not say. */
    public static function of(MigrationStatementView $statement, string $column): ?self
    {
        $table = $statement->soleTarget(SchemaObjectType::Table);
        $before = $statement->migration->statementsBefore($statement->statementIndex);

        if (! $table instanceof StatementTarget || $before === null) {
            return null;
        }

        $type = null;

        foreach ($before as $digest) {
            $type = self::through($digest, $type, $table, $column);
        }

        return $type;
    }

    /** The column's type after one earlier statement, given what it was before that statement. */
    private static function through(MigrationStatementDigest $digest, ?self $type, StatementTarget $table, string $column): ?self
    {
        foreach ($digest->andItsActions() as $action) {
            $named = array_filter(
                $action->targets,
                static fn (StatementTarget $target): bool => $target->type === SchemaObjectType::Table && $target->identifier->name->canonical === $table->identifier->name->canonical,
            );

            // A statement about other tables leaves the column as it was. One nobody classified names
            // no target at all, so for that one the text is all there is to go on.
            if ($named === []) {
                $type = in_array($action->kind, [null, StatementKind::Unknown], true) && stripos($action->canonical, $table->identifier->name->canonical) !== false ? null : $type;

                continue;
            }

            // The same name under another qualification is another table, or this one in a spelling
            // the reading cannot match: either way, what it does is not followed.
            if (array_any($named, static fn (StatementTarget $target): bool => $target->qualifiedName() !== $table->qualifiedName())) {
                $type = null;

                continue;
            }

            $type = match ($action->kind) {
                // IF NOT EXISTS does nothing to a table or column that is already there.
                StatementKind::CreateTable => str_contains($action->canonical, 'IF NOT EXISTS') ? null : self::definedIn($action, $column),
                StatementKind::AddColumn => self::names($action, $column) ? self::definedIn($action, $column) : $type,
                StatementKind::DropColumn => self::names($action, $column) ? null : $type,
                StatementKind::DropTable, StatementKind::Rename, StatementKind::Unknown, null => null,
                default => $type,
            };
        }

        // A retyping that ran says what the column is from then on, whatever it was before.
        $retyped = ColumnTypeChange::ofColumnIn($digest->canonical, $column);

        return $retyped instanceof ColumnTypeChange && self::namesTheTable($digest, $table) ? new self($retyped->targetType()) : $type;
    }

    /** The type a statement defines the column with, or null when it defines none it could read. */
    private static function definedIn(MigrationStatementDigest $action, string $column): ?self
    {
        foreach ($action->columnDefinitions ?? [] as $definition) {
            if (trim($definition->name, '"') === $column) {
                return $definition->type === null ? null : new self(self::written($definition->type->name, $definition->size));
            }
        }

        return null;
    }

    /**
     * A canonical type name with its size, in PostgreSQL's spelling: a time type carries its precision
     * behind its first word, `timestamp(0) without time zone`, every other type behind its last.
     */
    private static function written(string $name, ?string $size): string
    {
        if ($size === null) {
            return $name;
        }

        return preg_match('/^(timestamp|time)\b/', $name) === 1 ? (string) preg_replace('/^(timestamp|time)\b/', '$1'.$size, $name, 1) : $name.$size;
    }

    /** Whether an action names the column as one it adds or drops. */
    private static function names(MigrationStatementDigest $action, string $column): bool
    {
        return array_any($action->targets, static fn (StatementTarget $target): bool => $target->type === SchemaObjectType::Column && trim($target->qualifiedName(), '"') === $column);
    }

    /** Whether a statement acts on the table under the qualification the judged statement uses. */
    private static function namesTheTable(MigrationStatementDigest $digest, StatementTarget $table): bool
    {
        return array_any($digest->targets, static fn (StatementTarget $target): bool => $target->type === SchemaObjectType::Table && $target->qualifiedName() === $table->qualifiedName());
    }
}
