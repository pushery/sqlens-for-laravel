<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L1;

use Override;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Mysql\DowntimeClass\MysqlDowntimeClassSource;
use Pushery\SQLens\Drivers\Mysql\DowntimeClass\NonDdlImpact;
use Pushery\SQLens\Drivers\Mysql\Rules\AbstractMysqlRule;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\NoSafeSequenceTemplate;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * `TRUNCATE` in a migration's `up()`, on MySQL — where it is a worse idea than on PostgreSQL, for a
 * reason that has nothing to do with locks.
 *
 * ## Why this is a MySQL rule and not the PostgreSQL one registered twice
 *
 * The destruction is the same; the recovery is not, and the recovery is what a reader needs.
 *
 * On PostgreSQL a `TRUNCATE` inside a transaction rolls back with it: a migration that fails after
 * one can still leave the table intact. On MySQL it cannot. `TRUNCATE` is **DDL**, so it causes an
 * implicit commit — measured, not assumed: Laravel's MySQL grammar reports
 * `supportsSchemaTransactions() === false`, and the server commits regardless of what the migrator
 * would have wrapped. The rows are gone the instant the statement runs, whatever happens afterwards
 * in the same migration, and `down()` is the only path back — one that cannot restore data.
 *
 * A rule that said the PostgreSQL sentence on MySQL would be telling a reader their transaction
 * protects them. It does not. That is why this is its own rule rather than a shared one with a
 * footnote: the difference is not an aside, it is the whole advice.
 *
 * ## What it does NOT re-decide
 *
 * The same-migration exception and the opt-in behavior follow the PostgreSQL rule exactly, because
 * those parts genuinely are engine-neutral: a helper table this migration just created holds no
 * data a deploy would miss, and a migration that MEANT the loss declares it with
 * `#[SqlensAllowDestructive]` — which does not silence the finding, it turns it into a named,
 * visible suppression with its reason shown.
 */
final class TruncateRule extends AbstractMysqlRule implements ProvidesRemediation
{
    private readonly MysqlDowntimeClassSource $downtimeClasses;

    /** The considered `none` — what to do instead is a decision about somebody's data. */
    private readonly NoSafeSequenceTemplate $template;

    public function __construct(string $projectRoot, ?MysqlDowntimeClassSource $downtimeClasses = null)
    {
        parent::__construct($projectRoot);

        $this->downtimeClasses = $downtimeClasses ?? new MysqlDowntimeClassSource;
        $this->template = new NoSafeSequenceTemplate;
    }

    /**
     * A considered `none` — with MySQL's sentence, not PostgreSQL's.
     *
     * The PostgreSQL sibling's reason is about what to do INSTEAD, and every word of it applies
     * here: reference data being reloaded wants an idempotent seeder, a table being retired wants
     * the staged drop, a fixture in the wrong file wants deleting. What it cannot carry is the fact
     * that makes this rule its own — on MySQL `TRUNCATE` is DDL and causes an implicit commit, so
     * the rows are gone the instant it runs and no failure later in the same migration brings them
     * back. A reader given the PostgreSQL wording would believe a transaction protects them.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if ($this->judge($statement) === null) {
            return null;
        }

        return $this->template->payload(
            'sqlens::messages.remediation.no_safe_sequence.truncate_mysql',
            'sqlens::messages.remediation.no_safe_sequence.verification',
            $this->id(),
            $this->downtimeClass(),
        );
    }

    public function id(): string
    {
        return 'MY.L1.TRUNCATE';
    }

    public function level(): Level
    {
        return Level::Destructive;
    }

    /**
     * From the non-DDL derivation, not from a literal here.
     *
     * `TRUNCATE` has no online-DDL matrix entry and never will — the matrix describes schema
     * changes, and this replaces a table's storage rather than altering its definition. That is
     * exactly the case the second, equally central derivation exists for, so the class comes from
     * there: {@see NonDdlImpact::StorageReplacement}, which is `rewrite`.
     *
     * `rewrite` rather than `online` even though MySQL's TRUNCATE is fast: the axis models what
     * happens to the TABLE, and a statement that discards every row is not something a caller
     * treating `rewrite` as "needs a window" is wrong to pause on.
     */
    #[Override]
    public function downtimeClass(): DowntimeClass
    {
        return $this->downtimeClasses->forNonDdl(NonDdlImpact::StorageReplacement);
    }

    #[Override]
    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $statement->is(StatementKind::TruncateTable)) {
            return null;
        }

        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget && $statement->migration->createsTable($table->qualifiedName())) {
            return null;
        }

        return 'TRUNCATE in up() empties the table with no confirmation and no predicate to limit it — and on '
            .'MySQL there is no transaction to take it back. TRUNCATE is DDL here, so it causes an implicit '
            .'commit: the rows are gone the instant the statement runs, whatever fails later in the same '
            .'migration, and down() is the only way back — one that cannot restore data. If you need the table '
            .'emptied and the rows recoverable, take a backup first, or DELETE in bounded batches so the work is '
            .'reversible while it runs. If the loss is intended, annotate the migration with '
            .'#[SqlensAllowDestructive] and a reason — that does not hide the finding, it records who decided.';
    }
}
