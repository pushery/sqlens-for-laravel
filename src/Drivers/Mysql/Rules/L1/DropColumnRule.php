<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L1;

use Override;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\DerivesDowntimeClass;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Mysql\DowntimeClass\MysqlDowntimeClassSource;
use Pushery\SQLens\Drivers\Mysql\Rules\AbstractMysqlRule;
use Pushery\SQLens\Engine\ResolvedServerVersion;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\DeployWindowDropTemplate;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * `DROP COLUMN` in a migration's `up()`, on MySQL.
 *
 * The sibling of {@see DropTableRule} and built in the same change, for the same reason: the
 * destructive level-1 group existed only on PostgreSQL, so a column drop produced a finding there
 * and silence here.
 *
 * ## Its downtime class is CONDITIONAL, and that is the interesting part
 *
 * The class is never named in this file — it comes from the online-DDL matrix, whose `drop_column`
 * entry is `INSTANT` with `lock: none` and **four conditions** that take it off that path: a
 * functional index over the column, a table already out of instant row-version budget,
 * `ROW_FORMAT=COMPRESSED`, and a `FULLTEXT` index on the table.
 *
 * A caller that decided nothing about the live table gets the blind context, and a conditional
 * entry then resolves to **undetermined** rather than to its cheap case. That is the honest answer:
 * one of those four turns the statement into a full rebuild, and the row-version one makes the
 * server **refuse it outright** rather than fall back. Reporting `instant` from a static read would
 * be a promise the server has not made.
 *
 * ## Why the message is not the PostgreSQL one
 *
 * PostgreSQL only MARKS a column dropped — no rewrite, the space returns later. MySQL has no such
 * state, and `DROP COLUMN` is DDL, so it causes an implicit commit: the column and its data are
 * gone the instant the statement runs, whatever fails afterwards in the same migration.
 */
final class DropColumnRule extends AbstractMysqlRule implements DerivesDowntimeClass, ProvidesRemediation
{
    /** The matrix key this rule is about — the class comes from there and is never named here. */
    private const string OPERATION = 'drop_column';

    private readonly MysqlDowntimeClassSource $downtimeClasses;

    private readonly DeployWindowDropTemplate $template;

    public function __construct(string $projectRoot, ?MysqlDowntimeClassSource $downtimeClasses = null)
    {
        parent::__construct($projectRoot);

        $this->downtimeClasses = $downtimeClasses ?? new MysqlDowntimeClassSource;
        $this->template = new DeployWindowDropTemplate;
    }

    public function id(): string
    {
        return 'MY.L1.DROP_COLUMN';
    }

    public function level(): Level
    {
        return Level::Destructive;
    }

    /** From the matrix, for the one operation this rule is about — never named in this file. */
    public function downtimeClassFor(MigrationStatementView $statement): ?DowntimeClass
    {
        if ($this->judge($statement) === null) {
            return null;
        }

        return $this->downtimeClasses->forCandidateOperations(
            [self::OPERATION],
            $statement->serverVersion ?? ResolvedServerVersion::unresolvable(),
        )->downtimeClass;
    }

    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if ($this->judge($statement) === null) {
            return null;
        }

        // The class may be null here — the matrix entry is conditional, so a run that decided
        // nothing about the live table has no window to look it up in. The staged drop is the same
        // sequence either way, which is why the template takes it nullable.
        return $this->template->forColumn(
            $this->columnContext($statement),
            $this->id(),
            $this->downtimeClassFor($statement),
        );
    }

    /**
     * The table and column this statement names, as the classifier resolved them.
     *
     * @return array<string, string>
     */
    private function columnContext(MigrationStatementView $statement): array
    {
        $context = [];
        $table = $statement->soleTarget(SchemaObjectType::Table);
        $column = $statement->soleTarget(SchemaObjectType::Column);

        if ($table instanceof StatementTarget) {
            $context['table'] = $table->qualifiedName();
        }

        if ($column instanceof StatementTarget) {
            $context['column'] = $column->qualifiedName();
        }

        return $context;
    }

    #[Override]
    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $statement->is(StatementKind::DropColumn)) {
            return null;
        }

        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget && $statement->migration->createsTable($table->qualifiedName())) {
            return null;
        }

        return 'DROP COLUMN in up() irreversibly deletes the column and its data — and on MySQL there is '
            .'no transaction to take it back. DROP COLUMN is DDL here, so it causes an implicit commit: '
            .'the values are gone the instant the statement runs, whatever fails later in the same '
            .'migration, and down() can add the column back but not what was in it. Stop writing and '
            .'reading it in a shipped release first, then drop it later. If the loss is intended, '
            .'annotate the migration with #[SqlensAllowDestructive] and a reason — that does not hide '
            .'the finding, it records who decided.';
    }
}
