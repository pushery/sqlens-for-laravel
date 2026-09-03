<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L9;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Contracts\JudgesMigrationStatements;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Pedantic\SelectStarInView;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * `SELECT *` in a view definition, which PostgreSQL freezes into a fixed column list.
 *
 * Measured against PostgreSQL 18.4: a view over `SELECT *` on a two-column table reads back as
 * `SELECT a, b FROM t` from `pg_get_viewdef`. Add a third column to the table and it reads back the same way — the view does not
 * grow, and nothing about the `ALTER TABLE` says so. The view has to be REPLACED.
 *
 * That delay is what makes it a rule rather than a preference. The migration that adds the column
 * is green, the deploy is green, and the report that quietly lacks the new column is noticed weeks
 * later by somebody who does not know a view is involved.
 *
 * ## The two suites answer DIFFERENT questions here, and only one of them can
 *
 * - **lint reads the migration**, where the star is still written down. This is the real check.
 * - **audit reads the catalog**, where the star no longer exists — PostgreSQL expanded it on
 *   the way in. The audit half therefore reports `undetermined` for every view, naming
 *   {@see UndeterminedReason::ServerExpandedDefinition} and pointing at the suite that can answer.
 *
 * The audit half is NOT decoration. A rule that simply left the audit suite would let a run over a
 * schema full of views report nothing at all about them, and a reader would take the silence for a
 * clean result. This package's first principle is that a check which cannot run says so.
 */
final class SelectStarInViewRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes, JudgesMigrationStatements
{
    public function id(): string
    {
        return 'PG.L9.VIEW_SELECT_STAR';
    }

    public function level(): Level
    {
        return Level::Pedantic;
    }

    public function category(): Category
    {
        return Category::Idiom;
    }

    /**
     * Online — and there IS an operation to price here, which is what earns the answer.
     *
     * The flagged statement is a `CREATE VIEW`: it takes no lock on data, rewrites no table, and
     * costs a deploy nothing on either engine. So `online` is literally true of it rather than a
     * convenient way to fill the field, and a release gate reading it is told the correct thing —
     * this finding does not hold up the deploy.
     *
     * The remedy is priced the same way: naming the columns is an edit to the same statement, made
     * before it ever runs. The audit half prices nothing at all, because it reaches no verdict about
     * an operation — it answers undetermined and sends the reader to the migration.
     */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Lint, Suite::Audit];
    }

    /** @return non-empty-list<SchemaObjectType> */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::View, SchemaObjectType::MaterializedView];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::View && $object->type !== SchemaObjectType::MaterializedView) {
            return [];
        }

        return [RuleVerdict::undetermined(
            // Worded so it does not READ as SQL. The reader-relation audit scans shipped strings for a
            // `select` near a `from`, and an earlier draft of this sentence tripped it — the guard
            // extracted `the` as a relation this rule reads without an allowlist entry. The guard was
            // right to look; the sentence was the thing to change.
            'Whether `'.$object->qualifiedName.'` was defined with a star column list cannot be established '
            .'here: PostgreSQL resolved the star into a fixed set of columns when the view was created and '
            .'kept only that result. The migration still holds what was written — run the lint suite over it.',
            UndeterminedReason::ServerExpandedDefinition,
        )];
    }

    public function judgeStatement(MigrationStatementView $statement): ?RuleVerdict
    {
        if (! SelectStarInView::isViewDefinition($statement->canonical)) {
            return null;
        }

        // A view whose definition has no select list to read — `AS VALUES (…)`, `AS TABLE t`. Not a
        // pass: the rule looked and could not see, which is a different fact from looking and
        // finding nothing. Silently passing here is the exact shape this package refuses.
        if (SelectStarInView::selectList($statement->canonical) === null) {
            return RuleVerdict::undetermined(
                'This statement creates a view in a form whose select list SQLens does not read, so whether it '
                .'expands a `*` is unknown. The check did not pass — it did not run.',
                UndeterminedReason::UncanonicalizableStatement,
            );
        }

        $stars = SelectStarInView::stars($statement->canonical);

        if ($stars === []) {
            return null;
        }

        $named = count($stars) === 1
            ? '`'.$stars[0].'`'
            : implode(', ', array_map(static fn (string $star): string => '`'.$star.'`', $stars));

        return RuleVerdict::flag(
            'This view selects '.$named.', and PostgreSQL expands that into a fixed column list when the '
            .'view is created. A column added to a base table later never appears in the view, and no migration '
            .'says so — the view has to be replaced. Name the columns the view is meant to expose.',
        );
    }
}
