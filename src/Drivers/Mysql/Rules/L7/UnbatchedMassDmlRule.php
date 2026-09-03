<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L7;

use Override;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Deploy\Contracts\DeclaresOperationClass;
use Pushery\SQLens\Drivers\Mysql\DowntimeClass\MysqlDowntimeClassSource;
use Pushery\SQLens\Drivers\Mysql\DowntimeClass\NonDdlImpact;
use Pushery\SQLens\Drivers\Mysql\Rules\AbstractMysqlRule;
use Pushery\SQLens\Drivers\Mysql\Rules\Support\MysqlBulkWriteBounds;
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
 * It is a **heuristic**, and the finding says so in its own words. What the rule can see is that
 * the statement carries no bound; what it cannot see is how many rows that means. A hundred rows
 * and a hundred million produce the identical SQL, and the difference between a non-event and an
 * outage is entirely in the table, not in the statement. Reading the table's size would mean
 * querying the server, which the lint suite deliberately does not do — the statistics-weighted
 * escalation belongs to the deploy suite, where a run is allowed to look.
 *
 * ## What MySQL makes visible that PostgreSQL does not
 *
 * MySQL supports `UPDATE … LIMIT n`, and Laravel's MySQL grammar emits it verbatim from
 * `->limit(1000)`. So on MySQL a chunked write is READABLE in the statement:
 *
 * ```
 * UPDATE orders SET status = 'new' WHERE status = 'old' LIMIT 1000
 * ```
 *
 * PostgreSQL has no such clause, and Laravel emulates the same call as
 * `WHERE ctid IN (SELECT … LIMIT n)` — a different shape entirely. Measured on both engines, and
 * it is the reason this rule is MySQL's rather than a driver-neutral one: the SIGNAL is
 * engine-specific even though the hazard is not.
 *
 * ## Where the boundary with the other write rules runs
 *
 * Three rules can look at one data statement, and they ask three different questions. Keeping them
 * apart is what stops a single `UPDATE` from producing three findings that a reader learns to skim:
 *
 * - `GEN.L1.DML_WITHOUT_WHERE` — **correctness**: there is no predicate at all, so the statement
 *   touches every row whether or not that was meant. This rule stays silent there, because that
 *   statement's problem is not that it is unbatched.
 * - `MY.L3.MIXED_DDL_DML_NOT_ATOMIC` — **atomicity**: a write that follows a schema change in the
 *   same migration cannot be rolled back past the implicit commit.
 * - this rule — **size**: the predicate is there and the write is still unbounded.
 *
 * ## Why a `BETWEEN` silences it
 *
 * A key-range predicate is the chunking pattern this rule's own advice recommends, and Laravel
 * emits it with no `LIMIT` at all (`WHERE id BETWEEN 1 AND 1000`). Flagging it would be crying
 * wolf on the fix — and a linter that flags the recommended pattern is one a team turns off, at
 * which point it protects nothing. The leniency is deliberate and it errs toward a false NEGATIVE:
 * a `BETWEEN` on a non-key column bounds nothing, and this rule will not say so.
 */
final class UnbatchedMassDmlRule extends AbstractMysqlRule implements DeclaresOperationClass, ProvidesRemediation
{
    private readonly MysqlDowntimeClassSource $downtimeClasses;

    /** The one batch recipe in the package, built once — driver-neutral, and shared with expand/contract. */
    private readonly BatchedBackfillTemplate $template;

    public function __construct(string $projectRoot, ?MysqlDowntimeClassSource $downtimeClasses = null)
    {
        parent::__construct($projectRoot);

        $this->downtimeClasses = $downtimeClasses ?? new MysqlDowntimeClassSource;
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
    #[Override]
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        // The recipe rewrites a bulk write into chunks, so it needs one to rewrite. Whether that
        // write is already bounded, and whether the table was created by this same migration, are
        // left to the judgment: those decide if the rule has anything to SAY, not whether the plan
        // describes the statement.
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
        return 'MY.L7.UNBATCHED_MASS_DML';
    }

    /**
     * Level 7 — performance heuristics, and the level is the honesty.
     *
     * The rule cannot tell a large table from a small one, so it belongs in the band a project
     * turns on when it has decided it wants estimates as well as facts. Putting it lower would
     * make an unbounded write on a ten-row lookup table fail a level-2 gate.
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
     * From the non-DDL derivation, never a literal here.
     *
     * A data write is not a schema change, so the online-DDL matrix has no entry for it and never
     * will. {@see NonDdlImpact::WholeTableWrite} is the case written for exactly this: a write
     * "whose predicate cannot bound it", whose lock reach is therefore the whole table —
     * `blocking`. The class describes the REACH of the statement, not a guess at its duration,
     * which is the one thing a static reader has no business estimating.
     */
    #[Override]
    public function downtimeClass(): DowntimeClass
    {
        return $this->downtimeClasses->forNonDdl(NonDdlImpact::WholeTableWrite);
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
            ? BulkWrite::parse($statement->canonical, new MysqlBulkWriteBounds)
            : null;
    }

    #[Override]
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
            .'the predicate matches — holding row locks and growing the undo log for as long as that takes, while '
            .'the migration blocks the deploy. This is a HEURISTIC: SQLens can see that the statement is unbounded, '
            .'not how many rows that means, and it never asks the server for a row count. On a small table this is '
            .'a non-event. Bound it: MySQL accepts LIMIT on UPDATE and DELETE, so add ->limit(1000) and repeat, or '
            .'walk a key range with ->whereBetween(\'id\', [$from, $to]) — either one silences this. Better still '
            .'for a large table, move the backfill out of the migration into a queued job, so a deploy is not '
            .'waiting on it.';
    }

    private function insertMessage(): string
    {
        return 'This INSERT reads its rows from a SELECT with nothing bounding it, so it copies however many rows '
            .'the source table holds in one statement — reading the whole source and locking as it goes, while the '
            .'migration blocks the deploy. This is a HEURISTIC: SQLens can see that the statement is unbounded, not '
            .'how many rows that means, and it never asks the server for a row count. Bound the SELECT (a LIMIT, or '
            .'a key range walked in chunks), or move the copy out of the migration into a queued job so a deploy is '
            .'not waiting on it.';
    }
}
