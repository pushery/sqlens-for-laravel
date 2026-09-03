<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L2;

use Override;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\DerivesDowntimeClass;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Deploy\Contracts\DeclaresOperationClass;
use Pushery\SQLens\Drivers\Mysql\DowntimeClass\MysqlDowntimeClassSource;
use Pushery\SQLens\Drivers\Mysql\OnlineDdl\DowntimeClassMapping;
use Pushery\SQLens\Drivers\Mysql\Rules\AbstractMysqlRule;
use Pushery\SQLens\Drivers\Mysql\Rules\Support\ColumnRedefinition;
use Pushery\SQLens\Engine\ResolvedServerVersion;
use Pushery\SQLens\Findings\Confidence;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\ExpandContractTemplate;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A column redefinition — what Laravel's `->change()` compiles to — that rebuilds the whole
 * table. On a large, live table an `ALGORITHM=COPY` rebuild is a full copy of every row under a
 * shared lock: writes queue for the duration, and the duration grows with the table.
 *
 * ## What the statement settles, and what it cannot
 *
 * MySQL's `MODIFY` takes the column's WHOLE definition, never a delta. `MODIFY total BIGINT NOT
 * NULL` is what you write to change the type — and also what you write to flip the nullability,
 * to move the column, or to change nothing at all. Which it turns out to be depends on the
 * column's CURRENT definition, which no migration contains. That is why this rule is
 * {@see Confidence::Heuristic}: the shape it reports is right, the certainty is bounded, and a
 * reader must see the margin rather than read the verdict as proof.
 *
 * The measurements this rests on were taken against a real MySQL 8.4, not recalled — each
 * redefinition run under `ALGORITHM=INSTANT` then `ALGORITHM=INPLACE` to see which the server
 * accepts:
 *
 * | Redefinition (same column, differing in…) | MySQL 8.4 runs it |
 * |---|---|
 * | the data type (`INT` → `BIGINT`) | COPY |
 * | a VARCHAR shrink (`100` → `60`) | COPY |
 * | a VARCHAR extension across the length-prefix byte class (`63` → `64`, utf8mb4) | COPY |
 * | a VARCHAR extension within it (`100` → `200`, utf8mb4) | INPLACE, no rebuild |
 * | the nullability, either way | INPLACE, with rebuild |
 * | the column position (`AFTER`) | INPLACE, with rebuild |
 * | the DEFAULT only | INSTANT |
 * | nothing at all | INSTANT |
 *
 * ## The one exception this rule knowingly reports over
 *
 * A redefinition whose only delta is the DEFAULT is INSTANT, and this rule flags it anyway,
 * because the statement gives no way to tell it from a type change. That is a deliberate
 * asymmetry, not an oversight: a false positive costs a reader one look at the column, a false
 * negative costs an outage. `set_column_default` is therefore not among the candidate operations
 * below — including it would make the candidate set disagree on the class and turn EVERY
 * redefinition into an undetermined, which is a rule that reports nothing at all.
 *
 * ## VARCHAR is the honest undetermined
 *
 * VARCHAR is the one type MySQL can resize without rebuilding, and only in one direction and only
 * while the length prefix keeps its byte size (1 byte below 256 bytes of storage, 2 at or above).
 * Both facts turn on the CURRENT length, so a VARCHAR redefinition is reported as
 * {@see UndeterminedReason} rather than flagged — and the reason comes from the matrix's own
 * condition on that entry, not from a judgment made here.
 *
 * ENUM and SET are handed over untouched: appending a member is instant, inserting one in the
 * middle is a COPY, and that distinction is a rule of its own rather than a footnote to this one.
 *
 * ## The downtime class is derived, never declared
 *
 * The rule names the operations the statement COULD be performing; the online-DDL matrix decides
 * what they cost. If a future matrix revision ever made two of them disagree, the derivation
 * returns undetermined on its own rather than continuing to report a class they no longer share
 * — which is why this implements {@see DerivesDowntimeClass} instead of stamping a constant.
 *
 * It therefore declares NO {@see Rule::downtimeClass()} of its own, and that absence is
 * deliberate. A constant beside the derivation would be a second statement of the same fact, in
 * the one file that must not make it: a class named here could disagree with the matrix and
 * nothing would notice, because the collector reads the derived value. The catalog says
 * `downtime_class_derived` rather than inventing one, so a reader can still tell "no class" from
 * "decided per statement".
 */
final class CopyAlterTypeRule extends AbstractMysqlRule implements DeclaresOperationClass, DerivesDowntimeClass, ProvidesRemediation
{
    /**
     * The operations a redefinition of a NON-VARCHAR column could be performing, minus the
     * default-only case (see the class docblock). Every one of them rebuilds the table, which is
     * what lets the matrix answer with a single shared class — but that agreement is the
     * matrix's to state, and it is asked for it on every run rather than assumed here.
     *
     * @var list<string>
     */
    private const array REBUILDING_CANDIDATES = [
        'change_column_type',
        'make_column_not_null',
        'make_column_nullable',
    ];

    /**
     * The candidates for a VARCHAR column: the two directions of a resize. `extend_varchar` is
     * the matrix's one conditional entry here (`varchar_length_bytes_unchanged`), and a static
     * reader cannot decide that condition — so asking for both is what produces the honest
     * undetermined, from the matrix rather than from a branch in this file.
     *
     * @var list<string>
     */
    private const array VARCHAR_CANDIDATES = ['shrink_varchar', 'extend_varchar'];

    /** The operation a position clause names outright — added to whichever set applies. */
    private const string POSITION_CANDIDATE = 'reorder_column';

    private readonly MysqlDowntimeClassSource $downtimeClasses;

    /** The staged column swap this rule points at — the NEUTRAL sequence, shared with its PostgreSQL siblings. */
    private readonly ExpandContractTemplate $template;

    public function __construct(string $projectRoot, ?MysqlDowntimeClassSource $downtimeClasses = null)
    {
        parent::__construct($projectRoot);

        $this->downtimeClasses = $downtimeClasses ?? new MysqlDowntimeClassSource;
        $this->template = new ExpandContractTemplate;
    }

    /**
     * The staged column swap — and NOT the pinned `ALGORITHM`/`LOCK` clause, which is the
     * interesting decision here.
     *
     * The clause template reads its two values out of the matrix entry FOR THE OPERATION, and this
     * rule's whole finding is that the operation is not knowable from the statement: `MODIFY total
     * BIGINT NOT NULL` is what you write for a type change, for a nullability flip and for a move.
     * Measured on the shipped matrix, those do not share a clause — `change_column_type` is
     * `copy`/`shared`, `make_column_not_null` and `make_column_nullable` are `inplace`/`none`. So
     * naming one would be the guessed clause that template exists to refuse: `INPLACE` claims the
     * change is not a retype, `COPY` claims it is.
     *
     * What IS true whichever operation it turns out to be is the staged swap — add the new column,
     * backfill it in batches, cut over, drop the old one — which is what this rule's own finding
     * prescribes first. It is handed over for the UNDETERMINED verdict too (the VARCHAR case, and
     * an unresolvable server version): staging does not depend on the answer the matrix withheld,
     * and withholding the plan as well would leave the harder case with less help than the easy one.
     *
     * The pinned clause is not lost — the finding names it as the brake it is: `ALGORITHM=INPLACE,
     * LOCK=NONE` makes MySQL REFUSE rather than silently copy. That is a sentence about what to do
     * if the change must run in place, not a sequence, and `MY.L3.ALGORITHM_LOCK_UNEXPRESSIBLE`
     * carries the sequence for the statements where the operation IS known.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        $redefinition = $this->redefinitionIn($statement);

        if (! $redefinition instanceof ColumnRedefinition) {
            return null;
        }

        $context = ['old_column' => $redefinition->column];

        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget) {
            $context['table'] = $table->qualifiedName();
        }

        return $this->template->payload($context, $this->id(), $this->downtimeClassFor($statement));
    }

    public function id(): string
    {
        return 'MY.L2.COPY_ALTER_TYPE';
    }

    /**
     * MySQL's COPY algorithm builds a whole new table and swaps it, which is the same shape of cost as
     * a Postgres rewrite and is measured the same way: in bytes on disk.
     */
    public function operationClass(): string
    {
        return 'rewrite';
    }

    public function level(): Level
    {
        return Level::BlockingDdl;
    }

    /**
     * Heuristic, and the honest reason is one sentence: the statement carries the column's target
     * definition but not its current one, so "this changes the type" is an inference, not a
     * reading. The same boundary the PostgreSQL type-change rule carries, for the same cause.
     */
    #[Override]
    public function confidence(): Confidence
    {
        return Confidence::Heuristic;
    }

    /**
     * The class for THIS statement, from the matrix — or null when the matrix could not settle
     * it, in which case the verdict below is an undetermined and a class would contradict it.
     */
    public function downtimeClassFor(MigrationStatementView $statement): ?DowntimeClass
    {
        $redefinition = $this->redefinitionIn($statement);

        return $redefinition instanceof ColumnRedefinition
            ? $this->mappingFor($redefinition, $statement)->downtimeClass
            : null;
    }

    #[Override]
    protected function verdict(MigrationStatementView $statement): ?RuleVerdict
    {
        $redefinition = $this->redefinitionIn($statement);

        if (! $redefinition instanceof ColumnRedefinition) {
            return null;
        }

        $mapping = $this->mappingFor($redefinition, $statement);

        if ($mapping->isDetermined()) {
            return RuleVerdict::flag($this->rebuildMessage());
        }

        // The matrix could not settle it. For a VARCHAR that is the EXPECTED answer and the rule
        // explains which fact resolves it; for anything else the matrix hit a limit of its own
        // (an unknown server version, an unreadable file) and its reason is passed through rather
        // than reworded, so a reader is pointed at what actually blocked the lookup.
        return RuleVerdict::undetermined(
            $redefinition->isVarchar() ? $this->varcharMessage() : $this->unresolvedMessage($mapping),
            $mapping->reason ?? UndeterminedReason::OnlineDdlConditionUndecidable,
        );
    }

    /**
     * The redefinition this statement performs, or null when the rule has nothing to say about it
     * at all — it is not a redefinition, it is an enumerated type (a rule of its own), or the
     * table is born in this very migration.
     *
     * Both entry points — {@see verdict()} and {@see downtimeClassFor()} — start here, so a
     * finding's class and its verdict can never come from two different readings of one statement.
     */
    private function redefinitionIn(MigrationStatementView $statement): ?ColumnRedefinition
    {
        $redefinition = ColumnRedefinition::parse($statement->canonical);

        if (! $redefinition instanceof ColumnRedefinition || $redefinition->isEnumerated()) {
            return null;
        }

        // A column of a table created in this same migration holds no data to rebuild. The same
        // exception every column rule in this package carries, for the same reason.
        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget && $statement->migration->createsTable($table->qualifiedName())) {
            return null;
        }

        return $redefinition;
    }

    /** The matrix's answer for a redefinition this rule has decided to judge. */
    private function mappingFor(ColumnRedefinition $redefinition, MigrationStatementView $statement): DowntimeClassMapping
    {
        return $this->downtimeClasses->forCandidateOperations(
            $this->candidatesFor($redefinition),
            // No version reaches a subject built outside a run (the fast path with no pin is the
            // real case). The matrix answers per version window, so it says so — carrying the
            // run's own reason rather than one invented here.
            $statement->serverVersion ?? ResolvedServerVersion::unresolvable(),
        );
    }

    /**
     * The operations this redefinition could be performing.
     *
     * @return list<string>
     */
    private function candidatesFor(ColumnRedefinition $redefinition): array
    {
        $candidates = $redefinition->isVarchar() ? self::VARCHAR_CANDIDATES : self::REBUILDING_CANDIDATES;

        return $redefinition->positioned ? [...$candidates, self::POSITION_CANDIDATE] : $candidates;
    }

    private function rebuildMessage(): string
    {
        return 'This restates the column\'s whole definition, so the statement alone does not say which part of it '
            .'changes — and every change it can express rebuilds the table. A data type change runs with '
            .'ALGORITHM=COPY: a full copy of every row under a shared lock, with writes queuing for the duration. A '
            .'nullability flip or a column move rebuilds it in place, which costs the same pass over the data. Stage '
            .'the change instead: add the new column, backfill it in batches, cut over, then drop the old one. If it '
            .'must run in place, issue it as a raw statement with ALGORITHM=INPLACE, LOCK=NONE — MySQL then refuses '
            .'the statement rather than quietly copying the table. (A redefinition whose only change is the column\'s '
            .'default is instant; this rule cannot tell that case apart and reports it too.)';
    }

    private function varcharMessage(): string
    {
        return 'This redefines a VARCHAR column, the one case MySQL may run without rebuilding the table — and '
            .'whether it does turns on the column\'s CURRENT length, which the migration does not contain. Extending '
            .'a VARCHAR is in place as long as the length prefix keeps its byte size (one byte below 256 bytes of '
            .'storage, two at or above); shrinking it, or crossing that boundary, runs with ALGORITHM=COPY and '
            .'rewrites every row under a shared lock. Compare the target length against the column\'s current length '
            .'and character set before deploying, or issue the change as a raw statement with ALGORITHM=INPLACE, '
            .'LOCK=NONE so MySQL refuses it rather than copying the table.';
    }

    private function unresolvedMessage(DowntimeClassMapping $mapping): string
    {
        return 'This restates the column\'s whole definition, and whether MySQL rebuilds the table for it could not '
            .'be determined: '.($mapping->detail ?? 'the online-DDL matrix returned no entry for it')
            .'. The verdict is withheld rather than guessed — pin the server version with assume_server_version, or '
            .'issue the change as a raw statement with ALGORITHM=INPLACE, LOCK=NONE so MySQL refuses it rather than '
            .'copying the table.';
    }
}
