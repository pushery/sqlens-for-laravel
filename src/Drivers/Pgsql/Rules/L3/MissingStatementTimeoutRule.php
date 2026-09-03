<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L3;

use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Pgsql\Remediation\TimeoutPreambleTemplate;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L3\Support\ExpectedTimeouts;
use Pushery\SQLens\Drivers\Pgsql\Rules\L3\Support\StrongLockStatements;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Subjects\MigrationStatementDigest;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * The other half of level-3 timeout hygiene: `lock_timeout` bounds the WAIT for a lock,
 * `statement_timeout` bounds how long the operation runs once it HAS the lock. They fail
 * differently — one migration is stuck in the queue, the other holds an ACCESS EXCLUSIVE
 * lock for hours while it rewrites a billion-row table — so this is a rule of its own,
 * with its own id, page and finding, not a restatement of {@see MissingLockTimeoutRule}.
 *
 * It reuses the shared {@see StrongLockStatements} classification and ordering — the
 * strong-lock set and "is the timeout set BEFORE the first one?" question are defined
 * once and consumed here, never copied. It fires once per migration, on the first
 * strong-lock statement acting on a pre-existing object, when no `SET [LOCAL]
 * statement_timeout` appears before it. A `lock_timeout` alone does not satisfy it: the
 * two timeouts guard different failures, so a migration that sets one but not the other
 * gets exactly the finding for the one it is missing — proven by a de-dup test.
 *
 * Silent on a pure `CREATE TABLE` migration, on a lock against a table the same migration
 * just created, and when a project has narrowed `pgsql.expected_timeouts` to drop
 * `statement_timeout`.
 */
final class MissingStatementTimeoutRule extends AbstractPgsqlSafetyRule implements ProvidesRemediation
{
    /** The one preamble template, built once — it reads the shipped evidence register for its citation. */
    private readonly TimeoutPreambleTemplate $template;

    /**
     * @param  bool  $required  whether the project's `expected_timeouts` includes
     *                          `statement_timeout`; when it does not, the rule is
     *                          registered but stays silent — the shared config gate.
     */
    public function __construct(string $projectRoot, private readonly bool $required = true)
    {
        parent::__construct($projectRoot);

        $this->template = new TimeoutPreambleTemplate;
    }

    public function id(): string
    {
        return 'PG.L3.MISSING_STATEMENT_TIMEOUT';
    }

    /**
     * The preamble for the OTHER timeout — a different failure on a different axis.
     *
     * `statement_timeout` caps how long a statement RUNS once it holds its lock; the lock-timeout
     * rule next door caps how long it WAITS for one. Two rules, two findings, two one-line
     * preambles — so a migration missing only one is never told to add the one it already has.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        // This material reads nothing off the statement, which is what made it look
        // shape-independent. It is not. A timeout preamble is advice about a migration that takes
        // a strong lock on something it did not just create; handed one that takes none, it is a
        // work order for a problem that is not there. The reading is the same one the judgment
        // opens with, through one method rather than a second copy of it.
        if (! $this->gateStatement($statement) instanceof MigrationStatementDigest) {
            return null;
        }

        return $this->template->forTimeout(ExpectedTimeouts::STATEMENT_TIMEOUT, $this->id(), $this->downtimeClass());
    }

    /**
     * The statement whose lock this preamble is about, or null when the migration takes none.
     *
     * One reading, shared by the judgment and the fix material. Two copies of this call is the
     * way a finding and its plan end up disagreeing about the same migration.
     */
    private function gateStatement(MigrationStatementView $statement): ?MigrationStatementDigest
    {
        return StrongLockStatements::firstGateStatement($statement->migration->statements, $statement->migration);
    }

    public function level(): Level
    {
        return Level::LockHygiene;
    }

    /** Blocking: an operation that runs unbounded holds its lock the whole time, blocking the table. */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Blocking;
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $this->required) {
            return null;
        }

        $gate = $this->gateStatement($statement);

        // No strong lock on a pre-existing object: nothing here runs long while holding one.
        if (! $gate instanceof MigrationStatementDigest) {
            return null;
        }

        // Only the gate statement carries the finding, so the migration is flagged once.
        if ($gate->index !== $statement->statementIndex) {
            return null;
        }

        // A statement_timeout set anywhere before the gate already bounds the runtime. A
        // lock_timeout does NOT — that is the other rule's concern.
        if (StrongLockStatements::timeoutSetBefore($statement->migration->statements, $gate->index, ExpectedTimeouts::STATEMENT_TIMEOUT)) {
            return null;
        }

        return 'This migration takes a strong lock without first setting statement_timeout, so once it '
            .'has the lock it can run for as long as it takes — an ACCESS EXCLUSIVE lock held while a '
            .'large table is rewritten keeps the table unavailable the whole time. Set a statement_timeout '
            ."before the risky statement, for example DB::statement(\"SET statement_timeout = '30s'\"); at "
            .'the top of up(), so a run that overshoots aborts instead of holding the lock indefinitely. '
            .'This bounds the operation\'s RUNTIME; lock_timeout (PG.L3.MISSING_LOCK_TIMEOUT) bounds the '
            .'wait for the lock — different failures, both worth guarding.';
    }
}
