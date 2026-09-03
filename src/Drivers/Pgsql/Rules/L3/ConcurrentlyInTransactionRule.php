<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L3;

use Override;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Pgsql\Remediation\ConcurrentlyTemplate;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * `CREATE INDEX CONCURRENTLY` — and its siblings `DROP INDEX CONCURRENTLY` and
 * `REINDEX … CONCURRENTLY` — cannot run inside a transaction block: PostgreSQL raises
 * an error and does nothing. Laravel wraps a migration's `up()` in a transaction by
 * default, so this is the most common disappointment right after the well-meant switch
 * to `CONCURRENTLY`: the safe form is now written, and it fails on the first deploy.
 *
 * The fix is exact and the finding names it verbatim: `public $withinTransaction = false;`
 * on the migration class (Laravel 13). Outside a transaction, an interrupted concurrent
 * build can leave an INVALID index behind; cleaning that up is a later concern
 * (`sqlens:postdeploy`) and is only mentioned here, not solved.
 *
 * The transaction context comes from the migration's own `$withinTransaction`, carried
 * on the view — never from grammar internals, so the rule survives a Laravel major. It
 * is always determinate for a captured migration (the property has a default and is
 * always readable), so there is no unknown to hide and no silent green: the rule stays
 * silent only when the migration has definitively opted out of the transaction.
 */
final class ConcurrentlyInTransactionRule extends AbstractPgsqlSafetyRule implements ProvidesRemediation
{
    /** The concurrent-build sequence this rule points at, built once. */
    private readonly ConcurrentlyTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new ConcurrentlyTemplate;
    }

    public function id(): string
    {
        return 'PG.L3.CONCURRENTLY_IN_TRANSACTION';
    }

    /**
     * The concurrent-build sequence, whose second step IS this finding's fix.
     *
     * `public $withinTransaction = false;` is the line that is missing, and it is already step two
     * of the sequence the create-index rule hands over — so this rule points at that sequence
     * rather than carrying a one-line copy. A reader who lands here has written CONCURRENTLY and
     * got its habitat wrong; the rest of the sequence is what stops them getting the NEXT part
     * wrong too, which is the INVALID index an aborted build leaves behind.
     *
     * The statement is a create-index either way — the rule only fires on a CONCURRENTLY build —
     * so it is the create-side sequence, not the drop-side one.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        // TWO readings, because this rule's shape needs both — and the seam is the only caller that
        // has to make them itself. `verdict()` establishes the CONCURRENTLY half before `judge()`
        // ever runs, which is why the judgment can read the flag alone; a caller that comes in at
        // `remediationFor()` skips that gate entirely.
        //
        // Both halves matter to the material. Without the transaction, "run this outside the
        // transaction" is not a fix but a description of what already happens; without the
        // CONCURRENTLY build, the template names an index out of a statement that builds none.
        if (! $this->buildsConcurrently($statement) || ! $this->runsInsideTransaction($statement)) {
            return null;
        }

        return $this->template->forCreateIndex($statement, $this->id(), $this->downtimeClass());
    }

    /** Whether this statement runs inside a transaction — one reading, shared. */
    private function runsInsideTransaction(MigrationStatementView $statement): bool
    {
        return $statement->withinTransaction;
    }

    /**
     * Whether this statement builds concurrently at all — the gate `verdict()` opens with.
     *
     * On the canonical string, where the keyword is normalized to one casing, never on the
     * grammar's output.
     */
    private function buildsConcurrently(MigrationStatementView $statement): bool
    {
        return preg_match('/\bCONCURRENTLY\b/', $statement->canonical) === 1;
    }

    public function level(): Level
    {
        return Level::LockHygiene;
    }

    /**
     * Online: nothing about this locks the table. It is a hard failure at deploy time,
     * not a downtime — the danger is that the migration aborts, which the level captures.
     */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    /**
     * The three-valued verdict: the flag, else the honest "I could not tell".
     *
     * This rule turns entirely on one fact — does the statement run inside a transaction — and
     * the canonicalization can fail to resolve it (an explicit transaction opening inside the
     * migrator's, an unbalanced marker). The boolean it reads is true only for a DEFINITE
     * transaction, so an unresolved context arrived as "no" and the rule went quiet.
     *
     * Quiet is the worst available answer here. A CONCURRENTLY build inside a transaction does
     * not run slowly — PostgreSQL ABORTS it (25001) and the migration fails in the deploy.
     * Saying "I could not tell" costs a reader one line; saying nothing costs them the deploy.
     */
    #[Override]
    protected function verdict(MigrationStatementView $statement): ?RuleVerdict
    {
        if (! $this->buildsConcurrently($statement)) {
            return null;
        }

        if ($statement->transactionContextUnknown()) {
            return RuleVerdict::undetermined(
                'This builds CONCURRENTLY, which PostgreSQL aborts (25001) if it runs inside a '
                .'transaction — and whether this statement does could not be resolved. Set '
                .'public $withinTransaction = false; on the migration class to make the answer '
                .'explicit; reported rather than passed over because the failure mode is an aborted '
                .'deploy, not a slow one.',
                UndeterminedReason::TransactionContextUnknown,
            );
        }

        return parent::verdict($statement);
    }

    /**
     * The flag itself. Reached only through {@see self::verdict()}, which has already
     * established that the statement builds CONCURRENTLY — repeating the check here would be a
     * branch nothing can reach, and an unreachable branch is a branch nothing can test.
     */
    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $this->runsInsideTransaction($statement)) {
            return null;
        }

        return 'CONCURRENTLY cannot run inside a transaction, and Laravel wraps a migration\'s up() in '
            .'one by default, so PostgreSQL aborts this statement and does nothing. Set '
            .'public $withinTransaction = false; on the migration class so it runs outside a '
            .'transaction. Note that an interrupted concurrent build can then leave an INVALID index '
            .'behind, which needs cleaning up afterwards.';
    }
}
