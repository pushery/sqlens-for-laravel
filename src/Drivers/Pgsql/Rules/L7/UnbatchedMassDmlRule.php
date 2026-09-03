<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L7;

use Override;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Deploy\Contracts\DeclaresOperationClass;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\Support\PgsqlBulkWriteBounds;
use Pushery\SQLens\Findings\Confidence;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\BatchedBackfillTemplate;
use Pushery\SQLens\Rules\Data\BulkWrite;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A data write in a migration that nothing bounds — the backfill that runs as one statement over
 * however many rows the table happens to hold.
 *
 * The MySQL sister of this rule shipped first, and its docblock said why it was MySQL's alone: the
 * hazard is shared, but the SIGNAL is engine-specific. That was right about the signal and wrong
 * about the conclusion — PostgreSQL has a signal too, it just does not look like one.
 *
 * ## PostgreSQL cannot write `LIMIT` on an `UPDATE`, so a chunked write looks like this instead
 *
 * Read out of Laravel's own `PostgresGrammar` rather than guessed at:
 *
 * ```php
 * // compileUpdateWithJoinsOrLimit()
 * return "update {$table} set {$columns} where {$this->wrap('ctid')} in ({$selectSql})";
 * ```
 *
 * So `->limit(1000)` on this engine compiles to
 *
 * ```sql
 * update "orders" set "status" = ? where "ctid" in (select "orders"."ctid" from "orders" where … limit 1000)
 * ```
 *
 * A reader that looked for a top-level `LIMIT` would find one inside that subselect and be right by
 * accident — and would then also accept `UPDATE … WHERE id IN (SELECT id FROM other LIMIT 10)`,
 * where the `LIMIT` bounds the subquery and says nothing about the rows written. The `ctid` form is
 * matched as a SHAPE for that reason: it is the one construction in which a `LIMIT` on this engine
 * really does bound the write.
 *
 * ## It is a HEURISTIC, and the finding says so in its own words
 *
 * What the rule can see is that the statement carries no bound. What it cannot see is how many rows
 * that means — a hundred and a hundred million produce the identical SQL, and the difference
 * between a non-event and an outage is entirely in the table. Reading the table's size would mean
 * querying the server, which the lint suite deliberately does not do.
 *
 * ## Where the boundary with the other write rules runs
 *
 * The same three-way split its MySQL sister documents, and for the same reason — one `UPDATE` must
 * not produce three findings a reader learns to skim:
 *
 * - `GEN.L1.DML_WITHOUT_WHERE` — **correctness**: no predicate at all, so the statement touches
 *   every row whether or not that was meant. This rule stays silent there.
 * - `GEN.L3.DML_ON_SCHEMA_CHANGED_TABLE` — **atomicity**: a write against a table this migration
 *   also changed.
 * - this rule — **size**: the predicate is there and the write is still unbounded.
 */
final class UnbatchedMassDmlRule extends AbstractPgsqlSafetyRule implements DeclaresOperationClass, ProvidesRemediation
{
    /** The one batch recipe in the package, built once — driver-neutral, and shared with expand/contract. */
    private readonly BatchedBackfillTemplate $template;

    public function __construct(string $projectRoot)
    {
        parent::__construct($projectRoot);

        $this->template = new BatchedBackfillTemplate;
    }

    /**
     * The batching recipe, with the one fact this statement carries filled in.
     *
     * The table is fillable when the statement names exactly one; the batch size and the pause are
     * NOT, and never will be. They decide whether the backfill is invisible or is itself the
     * incident, and the values depend on row width, replica lag budget and traffic — none of which
     * is in the statement. This rule is a heuristic about SIZE precisely because size is what it
     * cannot see, so a payload that filled in a batch size would contradict the finding beside it.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if (! $this->bulkWrite($statement) instanceof BulkWrite) {
            return null;
        }

        $context = [];

        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget) {
            $context['table'] = $table->qualifiedName();
        }

        return $this->template->payload($context, $this->id(), $this->downtimeClass());
    }

    /**
     * `backfill` — and declaring it is what ARMS this rule.
     *
     * The shipped threshold artifact says of this class: *"a backfill that belongs in a queued job
     * looks identical to one that belongs in a migration until somebody knows how many rows it
     * touches. That is why the recommendation is deliberately unarmed without statistics and armed
     * by them."* This rule is the one that recommendation is about, and until it declared a class the
     * threshold had no producer — a line in a reviewable artifact that nothing could ever reach.
     *
     * That is the pairing exactly: the rule is a HEURISTIC about size and says so, and the deploy
     * suite — where a run is allowed to look at the server — raises the severity when the table
     * turns out to be large. The escalation creates no new rule class and invents no number; it
     * raises what this rule already found, records the threshold that fired, and keeps the base
     * severity so a baseline written on Monday still matches on Friday.
     */
    public function operationClass(): string
    {
        return 'backfill';
    }

    public function id(): string
    {
        return 'PG.L7.UNBATCHED_MASS_DML';
    }

    /**
     * Level 7 — performance heuristics, and the level is the honesty.
     *
     * The rule cannot tell a large table from a small one, so it belongs in the band a project turns
     * on when it has decided it wants estimates as well as facts. Putting it lower would make an
     * unbounded write on a ten-row lookup table fail a level-2 gate.
     */
    public function level(): Level
    {
        return Level::PerformanceHeuristics;
    }

    /**
     * Heuristic, and named as such on the finding too.
     *
     * The bound is a fact about the statement; whether the write is BIG is not in the statement at
     * all. A rule that reported this as deterministic would be claiming to know the row count.
     */
    #[Override]
    public function confidence(): Confidence
    {
        return Confidence::Heuristic;
    }

    /**
     * Blocking, declared — there is no matrix to derive it from and there never will be.
     *
     * The online-DDL matrix describes SCHEMA changes; a data write is not one. What the class says
     * here is the statement's REACH: an unbounded write holds row locks across whatever the
     * predicate matches, which is the whole table as far as a static reader can tell. It is not a
     * guess at duration, which is the one thing this rule has no business estimating.
     */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Blocking;
    }

    /**
     * The bulk write this statement is, or null when it is not one — one reading, shared.
     *
     * The kind check lives HERE rather than being repeated by each caller: `BulkWrite::parse()`
     * reads a canonical string and would happily be handed a DDL statement, so the two questions
     * belong together or they drift apart.
     */
    private function bulkWrite(MigrationStatementView $statement): ?BulkWrite
    {
        return $statement->is(StatementKind::Dml)
            ? BulkWrite::parse($statement->canonical, new PgsqlBulkWriteBounds)
            : null;
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        $write = $this->bulkWrite($statement);

        if (! $write instanceof BulkWrite || $write->isBounded()) {
            return null;
        }

        // A write on a table this migration just created has no accumulated rows to sweep — the
        // same exception every table-scoped rule here carries.
        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget && $statement->migration->createsTable($table->qualifiedName())) {
            return null;
        }

        return $write->isRowSource
            ? $this->insertMessage()
            : $this->updateMessage();
    }

    private function updateMessage(): string
    {
        return 'This write has a predicate but nothing that bounds it, so it runs as ONE statement over every row '
            .'the predicate matches — holding row locks and keeping a transaction open for as long as that takes, '
            .'while the migration blocks the deploy and autovacuum cannot clean up behind it. This is a HEURISTIC: '
            .'SQLens can see that the statement is unbounded, not how many rows that means, and it never asks the '
            .'server for a row count. On a small table this is a non-event. Bound it: PostgreSQL has no LIMIT on '
            .'UPDATE, so ->limit(1000) compiles to a ctid subselect — that counts — or walk a key range with '
            .'->whereBetween(\'id\', [$from, $to]). Better still for a large table, move the backfill out of the '
            .'migration into a queued job, so a deploy is not waiting on it.';
    }

    private function insertMessage(): string
    {
        // Worded so it does not READ as SQL. The reader-relation audit scans shipped strings for a
        // `select` near a `from`, and it is right to look — an earlier draft of this sentence made it
        // extract `a` as a relation this rule reads without an allowlist entry.
        return 'This INSERT takes its rows from a query with nothing bounding it, so it copies however many '
            .'rows the origin table holds in one statement — reading all of it and keeping a transaction open as '
            .'it goes, while the migration blocks the deploy. This is a HEURISTIC: SQLens can see that the reading '
            .'is unbounded, not how many rows it returns, and it never asks the server. The bound belongs on the '
            .'query rather than on the write: give it a key range, or move the copy out of the migration into a '
            .'queued job that walks the source in chunks.';
    }
}
