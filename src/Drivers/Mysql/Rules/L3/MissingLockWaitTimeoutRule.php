<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L3;

use Override;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Mysql\Remediation\TimeoutPreambleTemplate;
use Pushery\SQLens\Drivers\Mysql\Rules\AbstractMysqlRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L3\Support\MetadataLockStatements;
use Pushery\SQLens\Drivers\Mysql\Rules\L3\Support\MysqlTimeouts;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Subjects\MigrationStatementDigest;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * A MySQL migration takes a metadata lock without first bounding how long it will wait for one.
 *
 * ## Why MySQL needed its own rule rather than the PostgreSQL one renamed
 *
 * `SET lock_timeout` and `SET lock_wait_timeout` look like the same setting spelled two ways, and
 * they are not. PostgreSQL's caps the wait in the lock queue and takes an interval; MySQL's caps
 * the wait for a METADATA lock and takes seconds — and its default is
 * {@see MysqlTimeouts::LOCK_WAIT_TIMEOUT_DEFAULT_SECONDS}, one year. A rule copied across would
 * have demanded a setting MySQL does not have while leaving the one it does have unbounded.
 *
 * ## What this rule deliberately does NOT ask for
 *
 * There is no MySQL counterpart to `statement_timeout` for DDL, so this rule has no sibling asking
 * for one. `max_execution_time` is the setting that looks like the counterpart, and it is not: it
 * is milliseconds, it applies to read-only SELECT statements, and — measured on MySQL 8.4.10 — the
 * same work that a 200 ms limit killed as a `SELECT` ran 612 seconds uninterrupted once wrapped in
 * a `DO (…)`. Recommending it above an `ALTER TABLE` would promise a bound that demonstrably does
 * not reach the statement it is written above. See {@see MysqlTimeouts} for the full measurement.
 *
 * `innodb_lock_wait_timeout` is likewise not accepted: it bounds ROW locks, which a DDL does not
 * queue for.
 */
final class MissingLockWaitTimeoutRule extends AbstractMysqlRule implements ProvidesRemediation
{
    private readonly TimeoutPreambleTemplate $template;

    public function __construct(string $projectRoot)
    {
        parent::__construct($projectRoot);

        $this->template = new TimeoutPreambleTemplate;
    }

    /** The one line this migration is missing — the value left as a placeholder, never guessed. */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        return $this->judge($statement) === null
            ? null
            : $this->template->forLockWaitTimeout($this->id(), $this->downtimeClass());
    }

    public function id(): string
    {
        return 'MY.L3.MISSING_LOCK_WAIT_TIMEOUT';
    }

    public function level(): Level
    {
        return Level::LockHygiene;
    }

    /** Blocking: an unbounded metadata-lock wait stalls every statement that wants the same table. */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Blocking;
    }

    /**
     * @return list<string>
     */
    public function limitations(): array
    {
        return [
            'reads the migration\'s OWN statements. A project that sets `lock_wait_timeout` outside '
            .'the migration — in the connection options, a server default, or a listener — is bounded '
            .'and still reported here, because a static reader cannot see any of those',
            'says nothing about how long the statement RUNS once it has the lock. MySQL has no DDL '
            .'counterpart to a statement timeout: `max_execution_time` is milliseconds and applies to '
            .'read-only SELECTs, measured — the same work ran 612 seconds uninterrupted as a '
            .'non-SELECT under a 200 ms limit. So a bounded wait is not a bounded operation, and this '
            .'rule only claims the first',
            'does not accept `innodb_lock_wait_timeout` in place of `lock_wait_timeout`. They bound '
            .'different locks — row versus metadata — and a migration that set only the former has '
            .'not bounded what its DDL waits for',
        ];
    }

    #[Override]
    protected function judge(MigrationStatementView $statement): ?string
    {
        $gate = MetadataLockStatements::firstGateStatement($statement->migration->statements, $statement->migration);

        // Nothing waits on a lock queue: no metadata-locking statement, or only ones against tables
        // this same migration just created.
        if (! $gate instanceof MigrationStatementDigest) {
            return null;
        }

        // Only the gate statement carries the finding, so one migration produces one report rather
        // than one per risky statement.
        if ($gate->index !== $statement->statementIndex) {
            return null;
        }

        if (MetadataLockStatements::timeoutSetBefore($statement->migration->statements, $gate->index, MysqlTimeouts::LOCK_WAIT_TIMEOUT)) {
            return null;
        }

        return 'This migration takes a metadata lock without first setting lock_wait_timeout. MySQL '
            .'defaults that setting to 31536000 seconds — a year — so a statement that cannot get the '
            .'lock at once waits effectively forever, and every query wanting the same table queues '
            .'behind it. Worse than the wait itself: MySQL grants metadata locks in order, so one '
            .'blocked DDL blocks the readers behind it even though they only wanted to read. Set the '
            .'bound before the risky statement, for example DB::statement("SET SESSION '
            .'lock_wait_timeout = ?"); at the top of up(), so a blocked migration fails fast instead '
            .'of blocking everyone. Note that innodb_lock_wait_timeout is a different setting and '
            .'does not bound this wait, and max_execution_time does not apply to DDL at all.';
    }
}
