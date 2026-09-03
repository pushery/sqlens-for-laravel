<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L3;

use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Pgsql\Remediation\TransactionSplitTemplate;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L3\Support\StrongLockStatements;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Subjects\MigrationStatementDigest;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Several strong-lock operations bundled in ONE transaction hold every lock they take
 * until the single commit — the total lock time is the sum, not the max, and everything
 * queued behind any of those tables waits for the whole bundle. Laravel wraps a
 * migration's `up()` in one transaction by default, so a migration that alters three
 * different tables locks all three for the duration of the slowest. Level 3 flags the
 * bundle and points at the fix: split it into one migration per table, each committing
 * (and releasing) on its own.
 *
 * It reuses the shared {@see StrongLockStatements} reading — the strong-lock set, the
 * transaction context, the same-migration carve-out — and counts the DISTINCT
 * pre-existing tables locked within the transaction. More than {@see $maxLocks} of them
 * fires (the default of 1 flags a transaction that locks more than one table). Two
 * deliberate non-findings: several `ALTER` clauses in ONE statement are one lock on one
 * table (the desired batching, not a bundle), and a migration with
 * `public $withinTransaction = false;` takes its locks in separate transactions that each
 * commit on their own — no accumulation, so it is judged differently and stays silent.
 *
 * "DML + DDL on the same table in one transaction" is a different concern owned by a
 * separate lifecycle rule, and is deliberately NOT covered here.
 *
 * The transaction context comes from the migration's own `$withinTransaction`, carried on
 * the canonical view — never from a `BEGIN` string in the raw text. It is always
 * determinate for a captured migration (the property has a default and is always
 * readable), so there is no unknown to hide and no silent green.
 */
final class RiskyOpsSingleTransactionRule extends AbstractPgsqlSafetyRule implements ProvidesRemediation
{
    /** The split this rule hands over, built once. */
    private readonly TransactionSplitTemplate $template;

    /**
     * @param  int  $maxLocks  how many distinct existing tables one transaction may
     *                         strong-lock before the rule fires — the configurable
     *                         threshold (`pgsql.max_locks_per_transaction`), default 1.
     */
    public function __construct(string $projectRoot, private readonly int $maxLocks = 1)
    {
        parent::__construct($projectRoot);

        $this->template = new TransactionSplitTemplate;
    }

    /**
     * The split — and it carries no SQL, on purpose.
     *
     * The statements are already written; what is wrong is how they are GROUPED. Emitting them
     * again with different boundaries would mean reproducing somebody's migration, and the one
     * thing that could go wrong in doing so — the order between the new files — is exactly what
     * this rule cannot know.
     *
     * The finding already names the tables it counted, so the material does not repeat them either.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        // Splitting a transaction describes a migration that HAS strong locks to split. The
        // threshold below is not repeated here on purpose: how many locked tables are too many is
        // the judgment's business, while a migration with none at all is simply not what this
        // sequence is about.
        if ($this->transactionLocks($statement) === []) {
            return null;
        }

        return $this->template->payload($this->id(), $this->downtimeClass());
    }

    /**
     * The strong locks this migration takes inside one transaction — one reading, shared.
     *
     * @return list<MigrationStatementDigest>
     */
    private function transactionLocks(MigrationStatementView $statement): array
    {
        return StrongLockStatements::resolvableTransactionLocks($statement->migration->statements, $statement->migration);
    }

    public function id(): string
    {
        return 'PG.L3.RISKY_OPS_SINGLE_TX';
    }

    public function level(): Level
    {
        return Level::LockHygiene;
    }

    /** Blocking: every table locked in the transaction stays locked until commit, blocking its traffic. */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Blocking;
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        $locks = $this->transactionLocks($statement);

        if ($locks === []) {
            return null;
        }

        $tables = [];

        foreach ($locks as $lock) {
            $table = $lock->soleTarget(SchemaObjectType::Table);

            if ($table instanceof StatementTarget && ! in_array($table->qualifiedName(), $tables, true)) {
                $tables[] = $table->qualifiedName();
            }
        }

        // At or below the threshold — a single locked table (or however many the project
        // allows) is not the bundle this rule warns about.
        if (count($tables) <= $this->maxLocks) {
            return null;
        }

        // The finding is a transaction-level omission, so it is reported once, on the
        // first of the bundled statements.
        if ($locks[0]->index !== $statement->statementIndex) {
            return null;
        }

        return 'This migration takes a strong lock on '.count($tables).' different tables ('
            .implode(', ', $tables).') in a single transaction, and every one of those locks is held '
            .'until the whole migration commits — so the total lock time is the sum of the operations, '
            .'and traffic to any of those tables queues up behind the slowest. Split this into one '
            .'migration per table, so each takes its lock, commits, and releases it before the next '
            .'begins. Several ALTER clauses on the SAME table in one statement are fine — that is one '
            .'lock, not a bundle.';
    }
}
