<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L7;

use Override;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Pgsql\PgTypeChangeMatrix;
use Pushery\SQLens\Drivers\Pgsql\Remediation\AnalyzeAfterTemplate;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L2\TypeChangeRewriteRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\Support\ColumnTypeChange;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Subjects\MigrationStatementDigest;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * `ALTER COLUMN … TYPE` that rewrites nothing, with no `ANALYZE` of the table after it in the
 * migration: PostgreSQL removes the column's planner statistics all the same.
 *
 * Every form of `SET DATA TYPE` removes them, the free ones included: a binary-coercible change such
 * as `varchar(10)` to `varchar(20)`, and the type the column already has, which Laravel's `->change()`
 * names on every call, also when only the nullability or the default changes. The change adds nothing
 * to `n_mod_since_analyze`, so autovacuum has no reason to analyze the table again, and until ordinary
 * writes cross its threshold PostgreSQL plans every query on the column with default estimates.
 *
 * Where the change rewrites the table, or might, `PG.L2.TYPE_CHANGE_REWRITE` reports it and its
 * finding names the statistics too, so this rule stays silent there and a statement carries one
 * finding about them. A table the migration creates has no statistics to lose, and an `ANALYZE` of the
 * table later in the migration, or of the whole database, puts them back.
 *
 * A finding carries the fix as material: the change as written, then `ANALYZE` of the table in the
 * same migration.
 */
final class TypeChangeDropsStatisticsRule extends AbstractPgsqlSafetyRule implements ProvidesRemediation
{
    /** The rule whose finding names the statistics where the change rewrites the table, or might. */
    private readonly TypeChangeRewriteRule $rewrite;

    private readonly AnalyzeAfterTemplate $template;

    public function __construct(string $projectRoot, ?PgTypeChangeMatrix $matrix = null)
    {
        parent::__construct($projectRoot);

        $this->rewrite = new TypeChangeRewriteRule($projectRoot, $matrix);
        $this->template = new AnalyzeAfterTemplate;
    }

    /**
     * The change as written and an `ANALYZE` of its table after it, for a statement this rule
     * reports. The table is the one the statement names; where it names none the rule could read,
     * `{{table}}` stays visible.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if ($this->judge($statement) === null) {
            return null;
        }

        $table = $statement->soleTarget(SchemaObjectType::Table);

        return $this->template->payload(
            $table instanceof StatementTarget ? ['table' => $table->qualifiedName()] : [],
            $this->id(),
            $this->downtimeClass(),
        );
    }

    public function id(): string
    {
        return 'PG.L7.TYPE_CHANGE_DROPS_STATISTICS';
    }

    public function level(): Level
    {
        return Level::PerformanceHeuristics;
    }

    /** Online: the change is free. What it leaves behind is a plan built on default estimates. */
    #[Override]
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    #[Override]
    protected function judge(MigrationStatementView $statement): ?string
    {
        $change = ColumnTypeChange::of($statement);

        if (! $change instanceof ColumnTypeChange) {
            return null;
        }

        $table = $statement->soleTarget(SchemaObjectType::Table);
        $name = $table instanceof StatementTarget ? $table->qualifiedName() : null;

        if ($name !== null && $statement->migration->createsTable($name)) {
            return null;
        }

        if ($this->rewrite->reports($statement) || $this->analyzedLater($statement, $table, $change->column)) {
            return null;
        }

        return sprintf(
            'ALTER COLUMN … TYPE removes the planner statistics of %s, also where it rewrites nothing: a '
            .'binary-coercible change, or the type the column already has, which Laravel\'s ->change() names '
            .'on every call. Nothing about the change prompts autovacuum to analyze %s again, so until ordinary '
            .'writes cross its threshold PostgreSQL plans every query on the column with default estimates. Run '
            .'%s in this migration, after the change.',
            $change->column,
            $name ?? 'the table',
            $name !== null ? 'ANALYZE '.$name : 'ANALYZE on the table',
        );
    }

    /** Whether a statement after this one in the migration analyzes the table, or the whole database. */
    private function analyzedLater(MigrationStatementView $statement, ?StatementTarget $table, string $column): bool
    {
        return array_any(
            $statement->migration->statements,
            fn (MigrationStatementDigest $later): bool => $later->index > $statement->statementIndex
                && $this->analyzes($later->canonical, $table, $column),
        );
    }

    /**
     * Whether one statement analyzes the column's table: `ANALYZE` or `VACUUM` with the ANALYZE option,
     * naming the table, or naming no table at all and so taking the whole database. A column list on
     * the table counts only when it holds the column.
     */
    private function analyzes(string $canonical, ?StatementTarget $table, string $column): bool
    {
        $sql = strtolower(str_replace('"', '', trim($canonical)));

        if (preg_match('/^(analyze|vacuum)\b(.*)$/s', $sql, $statement) !== 1) {
            return false;
        }

        $rest = $statement[2];

        if ($statement[1] === 'vacuum' && preg_match('/\banalyze\b/', $rest) !== 1) {
            return false;
        }

        // The options: a parenthesized list, or the bare words of the older form, in front of the
        // tables.
        $rest = trim((string) preg_replace(
            ['/^\s*\([^)]*\)/', '/^\s*(?:(?:full|freeze|verbose|analyze)\b\s*)+/'],
            '',
            $rest,
        ), " \t\n;");

        if ($rest === '') {
            return true;
        }

        $wanted = $table instanceof StatementTarget ? strtolower($table->identifier->name->canonical) : null;
        $wantedColumn = strtolower(str_replace('"', '', $column));

        preg_match_all('/([a-z0-9_$.]+)\s*(?:\(([^)]*)\))?/', $rest, $entries, PREG_SET_ORDER);

        foreach ($entries as $entry) {
            $segments = explode('.', $entry[1]);

            if (end($segments) !== $wanted) {
                continue;
            }

            $columns = $entry[2] ?? '';

            if ($columns === '' || in_array($wantedColumn, array_map(trim(...), explode(',', $columns)), true)) {
                return true;
            }
        }

        return false;
    }
}
