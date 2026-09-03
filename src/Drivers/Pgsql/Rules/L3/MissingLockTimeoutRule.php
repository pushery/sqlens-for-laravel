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
 * A migration that takes a strong lock without first setting `lock_timeout` waits in the
 * lock queue for as long as it takes — and while it waits, everything that wants the same
 * table queues up behind it. A single `ALTER TABLE` stuck behind one long-running query
 * can stall an entire application. Level 3 asks a migration to bound its own lock wait.
 *
 * The rule fires on the FIRST strong-lock statement that acts on a pre-existing object
 * (see {@see StrongLockStatements}), when no `SET [LOCAL] lock_timeout` appears in the
 * stream before it. Order is the whole point: a timeout set AFTER the risky statement
 * does not protect it, so mere presence is not enough. It fires once per migration, on
 * that first statement, because the timeout is a migration-level omission, not a
 * per-statement one.
 *
 * Silent when the migration only creates tables, or only touches tables it itself just
 * created — a lock on a table nobody else can see yet blocks no one. Silent, too, when
 * a project has declared via `sqlens.pgsql.expected_timeouts` that it does not require
 * `lock_timeout`; the two timeout rules read that one config, each for its own timeout.
 *
 * Primum non nocere as a worked example, not just a sermon: SQLens sets `lock_timeout`
 * on its OWN capture session (`capture.session.lock_timeout`) before it runs, so the
 * rule asks of a migration exactly what the tool already does to itself.
 */
final class MissingLockTimeoutRule extends AbstractPgsqlSafetyRule implements ProvidesRemediation
{
    /** The one preamble template, built once — it reads the shipped evidence register for its citation. */
    private readonly TimeoutPreambleTemplate $template;

    /**
     * @param  bool  $required  whether the project's `expected_timeouts` includes
     *                          `lock_timeout` — when it does not, the rule is registered
     *                          (its metadata, its fixtures) but stays silent, the config
     *                          gate the two timeout rules share.
     */
    public function __construct(string $projectRoot, private readonly bool $required = true)
    {
        parent::__construct($projectRoot);

        $this->template = new TimeoutPreambleTemplate;
    }

    public function id(): string
    {
        return 'PG.L3.MISSING_LOCK_TIMEOUT';
    }

    /**
     * The one-line preamble that is missing, plus the decision it needs beside it.
     *
     * The timeout NAME comes from the same vocabulary the rule is gated on
     * ({@see ExpectedTimeouts}), so the payload can never recommend a setting the config surface
     * does not know. The VALUE stays a placeholder: a right `lock_timeout` depends on how long the
     * busiest transaction on that table runs and on how much deploy window there is, and neither is
     * in the migration.
     *
     * Not gated on `$required`: the collector only asks about a finding this rule produced, and a
     * rule that is switched off produces none.
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

        return $this->template->forTimeout(ExpectedTimeouts::LOCK_TIMEOUT, $this->id(), $this->downtimeClass());
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

    /** Blocking: the danger this names is a lock that waits unbounded and stalls the queue behind it. */
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

        // No strong lock on a pre-existing object: a pure create-table migration, or one
        // that only touches what it just created — nothing here waits on a lock queue.
        if (! $gate instanceof MigrationStatementDigest) {
            return null;
        }

        // Only the gate statement carries the finding, so the migration is flagged once.
        if ($gate->index !== $statement->statementIndex) {
            return null;
        }

        // A lock_timeout set anywhere before the gate already bounds the wait.
        if (StrongLockStatements::timeoutSetBefore($statement->migration->statements, $gate->index, ExpectedTimeouts::LOCK_TIMEOUT)) {
            return null;
        }

        return 'This migration takes a strong lock without first setting lock_timeout, so if the lock '
            .'cannot be acquired at once it waits in the queue indefinitely — and every statement that '
            .'wants the same table queues up behind it, which can stall the whole application. Set a '
            .'lock_timeout before the risky statement, for example DB::statement("SET lock_timeout = '
            .'\'3s\'\"); at the top of up(), so a blocked migration fails fast instead of blocking '
            .'everyone. SQLens sets lock_timeout on its own session for exactly this reason.';
    }
}
