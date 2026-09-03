<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L2;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Deploy\Contracts\DeclaresOperationClass;
use Pushery\SQLens\Drivers\Pgsql\Remediation\ConcurrentlyTemplate;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * `CREATE INDEX` without `CONCURRENTLY` takes a lock that blocks every write to the
 * table until the index is built. On a small table that is a blink; on a large,
 * live one it is an outage measured in minutes, and it is announced in advance by
 * the migration — which is exactly why a linter should catch it before it ships.
 *
 * The safe form is `CREATE INDEX CONCURRENTLY`, which builds without the write lock.
 * The finding names its own follow-on cost, because the fix has one: CONCURRENTLY
 * cannot run inside a transaction (see `PG.L3.CONCURRENTLY_IN_TRANSACTION`) and can
 * leave an INVALID index behind if it is interrupted, which a deploy has to clean up.
 * Naming it here keeps the rule from trading one silent problem for another.
 *
 * **The exception that keeps this rule usable.** An index on a table the SAME
 * migration just created is building against an empty table: there are no writers to
 * block and no rows to scan, so it is not the incident this rule warns about. Without
 * that carve-out the rule would fire on the commonest migration shape there is —
 * create a table, then index it — and a linter that flags the ordinary case is one a
 * team switches off. The check reads the migration context, never the SQL around it,
 * so it cannot be fooled by statement order or quoting.
 *
 * It reasons entirely on the classification: the KIND identifies a create-index, and
 * the TABLE target names what it indexes. Neither is read from the raw grammar — the
 * only string it inspects is the canonical form, and only for the CONCURRENTLY
 * keyword, which the classifier does not model as a kind of its own.
 */
final class CreateIndexNotConcurrentRule extends AbstractPgsqlSafetyRule implements DeclaresOperationClass, ProvidesRemediation
{
    /**
     * The one template this rule hands out, built once.
     *
     * Not built per finding, and the reason is measurable rather than stylistic: the template reads
     * the shipped evidence register to fill its references, and that read costs about 0.4 ms — free
     * once per run, and a bill that grows with the number of flagged migrations if it is paid per
     * finding. Held the same way {@see RuleDriverNotes} is on the base: resolved in the constructor,
     * immutable afterwards, so nothing about a verdict can depend on how often it was asked.
     */
    private readonly ConcurrentlyTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new ConcurrentlyTemplate;
    }

    public function id(): string
    {
        return 'PG.L2.INDEX_NOT_CONCURRENT';
    }

    /**
     * A non-concurrent build scans and sorts the table's ROWS while holding writes out. Rows rather than
     * bytes, because what the build walks is tuples — and the line sits far above the rewrite one,
     * since an index build over the same table is the cheaper of the two by a wide margin.
     */
    public function operationClass(): string
    {
        return 'index_build';
    }

    /**
     * The safe sequence, built from the classified statement rather than described in prose.
     *
     * The template owns the sequence; this method owns only the two facts that are the RULE's —
     * which rule the material is for, and the deploy impact it carries. The class is taken from
     * {@see self::downtimeClass()} rather than restated, so the finding and its fix material can
     * never make two different claims about what a deploy is in for.
     *
     * Narrowed to a non-null return, which the interface allows and PHPStan insists on: this rule
     * always has a sequence for the finding it produces, and a `?` here would invite a caller to
     * branch on an absence that cannot happen.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        // The SAME reading the judgment opens with, through one method rather than two copies of
        // one expression. The template fills the index, table and column names out of THIS
        // statement, so handed anything else it produces a CREATE INDEX CONCURRENTLY for an object
        // the migration never mentions.
        if (! $this->describesCreateIndex($statement)) {
            return null;
        }

        return $this->template->forCreateIndex($statement, $this->id(), $this->downtimeClass());
    }

    /** Whether this statement is the shape both the judgment and the fix material are about. */
    private function describesCreateIndex(MigrationStatementView $statement): bool
    {
        return $statement->is(StatementKind::CreateIndex);
    }

    public function level(): Level
    {
        return Level::BlockingDdl;
    }

    /**
     * Building an index without CONCURRENTLY blocks writers, so its deploy impact is
     * `blocking` — it degrades a live table without rewriting it. Named here rather
     * than inherited: the family default is "unset", because most safety rules cannot
     * claim one, but this one can and a reader plans a maintenance window around it.
     */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Blocking;
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $this->describesCreateIndex($statement)) {
            return null;
        }

        // The safe form. Checked on the canonical string — where the keyword is
        // normalized to one casing — not on Laravel's grammar output.
        if (preg_match('/\bCONCURRENTLY\b/', $statement->canonical) === 1) {
            return null;
        }

        // Building against a table this migration just created blocks nobody: no
        // writers, no rows. The one carve-out that keeps the rule from flagging the
        // ordinary create-then-index migration.
        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget && $statement->migration->createsTable($table->qualifiedName())) {
            return null;
        }

        return 'CREATE INDEX without CONCURRENTLY locks the table against writes until the '
            .'index is built — an outage on a large, live table. Use CREATE INDEX CONCURRENTLY, '
            .'which builds without that lock; note it cannot run inside a transaction and can '
            .'leave an INVALID index behind if interrupted.';
    }
}
