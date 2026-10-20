<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L3;

use Override;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\NoSafeSequenceTemplate;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * `VACUUM` in a migration that runs inside a transaction: PostgreSQL refuses it with error 25001.
 *
 * Every form of the statement is refused there, the plain `VACUUM` and `VACUUM ANALYZE` as much as
 * `VACUUM FULL`, and Laravel wraps a migration's `up()` in a transaction by default. The statement
 * does nothing and the migration fails on its first `migrate`. The fix is one line,
 * `public $withinTransaction = false;` on the migration class, in a migration of its own when the
 * statements beside it need their transaction.
 *
 * What `VACUUM FULL` costs once it runs is the business of `PG.L2.VACUUM_FULL`. This rule only says
 * whether it can run at all, so a `VACUUM FULL` in a transaction carries both findings, each about
 * one thing.
 *
 * The transaction context comes from the migration's own `$withinTransaction`, and an unresolved
 * context, such as an explicit transaction opening inside the migrator's, is reported as
 * undetermined rather than passed over: the failure it would hide is an aborted deploy.
 */
final class VacuumInTransactionRule extends AbstractPgsqlSafetyRule implements ProvidesRemediation
{
    /** The considered `none`: the fix is a property of the migration class, not a sequence of statements. */
    private readonly NoSafeSequenceTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new NoSafeSequenceTemplate;
    }

    /**
     * A considered `none`. The missing line is `public $withinTransaction = false;`, and where it
     * goes is a decision about the statements beside the `VACUUM`, which may need their transaction.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        // Both halves, because the seam comes in here without passing verdict(): a statement that
        // vacuums, and a transaction around it. Without the second the note would describe what
        // already happens.
        if (! $this->vacuums($statement) || ! $statement->withinTransaction) {
            return null;
        }

        return $this->template->payload(
            'sqlens::messages.remediation.no_safe_sequence.vacuum_in_transaction',
            'sqlens::messages.remediation.no_safe_sequence.vacuum_in_transaction_verification',
            $this->id(),
            $this->downtimeClass(),
        );
    }

    public function id(): string
    {
        return 'PG.L3.VACUUM_IN_TRANSACTION';
    }

    public function level(): Level
    {
        return Level::LockHygiene;
    }

    /** Online: the statement never runs, so nothing is locked. The danger is the aborted migration. */
    #[Override]
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    /** The flag, else the honest "could not tell" where the transaction context did not resolve. */
    #[Override]
    protected function verdict(MigrationStatementView $statement): ?RuleVerdict
    {
        if (! $this->vacuums($statement)) {
            return null;
        }

        if ($statement->transactionContextUnknown()) {
            return RuleVerdict::undetermined(
                'This runs VACUUM, which PostgreSQL refuses with error 25001 inside a transaction, and '
                .'whether this statement runs inside one could not be resolved. Set '
                .'public $withinTransaction = false; on the migration class to make the answer explicit; '
                .'reported rather than passed over because the failure mode is an aborted deploy.',
                UndeterminedReason::TransactionContextUnknown,
            );
        }

        return parent::verdict($statement);
    }

    /** The flag itself, reached only through {@see self::verdict()} for a statement that vacuums. */
    #[Override]
    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $statement->withinTransaction) {
            return null;
        }

        return 'VACUUM cannot run inside a transaction block, and Laravel wraps a migration\'s up() in one by '
            .'default, so PostgreSQL refuses this statement with error 25001 and the migration fails before it '
            .'does anything. Set public $withinTransaction = false; on the migration class, in a migration of '
            .'its own if the statements beside it need their transaction.';
    }

    /**
     * Whether the statement is a `VACUUM`, the plain form or the rewrite.
     *
     * On the canonical string, where the keyword is folded to one casing, and only for the two kinds
     * the classifier gives a `VACUUM`: `rebuild_table` for the rewrite and `unknown` for the rest.
     */
    private function vacuums(MigrationStatementView $statement): bool
    {
        return ($statement->is(StatementKind::RebuildTable) || $statement->is(StatementKind::Unknown))
            && preg_match('/^VACUUM\b/', $statement->canonical) === 1;
    }
}
