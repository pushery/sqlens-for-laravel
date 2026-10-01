<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Canonical\QuotedSpan;
use Pushery\SQLens\Canonical\StatementKind;
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
 * observe, so the whole statement is beneath notice when every table it names is new.
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
     * Where a query begins, asked at one offset: after an `AS`, or as a `SELECT` without one.
     */
    private const string QUERY_START = '/\G\b(?:AS(?:\s+(?:SELECT|TABLE|VALUES|WITH|EXECUTE)\b|\s*\()|SELECT\b)/i';

    /** The clause that runs no query: the table gets the query's columns and no rows. */
    private const string NO_DATA = '/\bWITH\s+NO\s+DATA\s*;?\s*$/i';

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

    /**
     * Whether the table this statement ACTS on is born empty in this migration.
     *
     * The narrower question {@see allCreatedHere()} cannot answer, and the one a validating
     * constraint actually turns on. `ADD CONSTRAINT` without `NOT VALID` differs from the safe form
     * in exactly one thing: it scans the rows already in the altered table, holding its locks for
     * as long as that takes. On a table this migration created two statements ago there are no
     * rows, the scan is instant, and the locks — SHARE ROW EXCLUSIVE on the altered table and, for
     * a foreign key, on the referenced one — are taken and released identically either way. The
     * remediation would split one migration into two and shorten no lock.
     *
     * That is why the REFERENCED table may be live here while {@see allCreatedHere()} insists both
     * are new: the referenced table's lock is real, but it is the same lock the safe form takes,
     * and the rule that judges waiting on it is the lock-timeout one.
     *
     * Three ways a table is NOT born empty, and each is checked rather than assumed:
     *
     *  - it was not created here at all,
     *  - it was created FROM A QUERY (`CREATE TABLE … AS SELECT`, `AS TABLE`, `AS (SELECT …)` and
     *    the other forms {@see filledByQuery()} names), so it has rows from birth,
     *  - an earlier statement in this migration writes into it — the create-then-backfill shape,
     *    where the scan is real and the advice worth taking.
     */
    public static function subjectBornEmptyHere(MigrationStatementView $statement): bool
    {
        $subject = array_find(self::of($statement), static fn (StatementTarget $table): bool => $table->isSubject());

        if (! $subject instanceof StatementTarget || ! $statement->migration->createsTable($subject->qualifiedName())) {
            return false;
        }

        $name = $subject->qualifiedName();

        foreach ($statement->migration->statements as $earlier) {
            if ($earlier->index >= $statement->statementIndex) {
                break;
            }

            $names = array_any(
                $earlier->targets,
                static fn (StatementTarget $target): bool => $target->type === SchemaObjectType::Table
                    && $target->qualifiedName() === $name,
            );

            if (! $names) {
                continue;
            }

            // A write into it, or the create that filled it. The query is read off the canonical
            // form because the classification says only that the statement creates the table — a
            // kind check alone would call a table born with a million rows empty. A missing column
            // body is no substitute: it also stands for a body the classifier declined, and every
            // ordinary create would then count as filled.
            if ($earlier->kind === StatementKind::Dml || ($earlier->kind === StatementKind::CreateTable && self::filledByQuery($earlier->canonical))) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether a `CREATE TABLE` fills the table from a query as it creates it.
     *
     * Read at parenthesis depth zero and outside every quoted span, where the column body cannot
     * reach: a generated column's `AS (…)` sits inside that body, and a table comment's text inside
     * a literal. PostgreSQL writes the query after an `AS` in six ways — `SELECT`, `TABLE s`,
     * `(SELECT …)`, `VALUES`, `WITH … SELECT` and `EXECUTE` of a prepared statement — and MySQL
     * also takes a `SELECT` with no `AS` before it. `WITH NO DATA` at the end runs none of them.
     */
    private static function filledByQuery(string $canonical): bool
    {
        if (preg_match(self::NO_DATA, $canonical) === 1) {
            return false;
        }

        $depth = 0;
        $at = 0;
        $length = strlen($canonical);

        while ($at < $length) {
            $char = $canonical[$at];

            if ($char === "'") {
                // MySQL's escape rules, because its table options are the only literals that stand
                // at depth zero before a query. On PostgreSQL a create with a column body has no
                // query to find, so a literal inside that body cannot hide one.
                $at = QuotedSpan::endOfLiteral($canonical, $at, $char, true) ?? $length;

                continue;
            }

            if ($char === '"' || $char === '`') {
                $at = QuotedSpan::endOfQuotedIdentifier($canonical, $at, $char) ?? $length;

                continue;
            }

            if ($char === '(' || $char === ')') {
                $depth = max(0, $depth + ($char === '(' ? 1 : -1));
                $at++;

                continue;
            }

            if ($depth === 0 && preg_match(self::QUERY_START, $canonical, offset: $at) === 1) {
                return true;
            }

            $at++;
        }

        return false;
    }
}
