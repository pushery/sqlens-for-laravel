<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Capture\SessionGuard;

/**
 * The session defense every shadow connection wears — the third promise of "first,
 * do no harm" (its own session timeouts), on the path that hangs longest and
 * closest to the source instance.
 *
 * The shadow mode opens several connections, and this defense is worn by the one that holds longest:
 * the registered shadow connection, bounded by {@see ShadowMigrationRunner::captureFrom()} before its
 * first real query. A shadow run must never itself become the database's problem.
 *
 * ⚠️ **IT SAID "EACH GETS BOUNDED" AND THAT WAS NOT TRUE, WHICH IS WORSE THAN THE GAP IT DESCRIBED.**
 * The defense is applied at ONE call site. Three connections of the shadow path run without it, and
 * saying otherwise is what an operator relies on when deciding whether to point shadow mode at a shared
 * instance. Each is named here instead:
 *
 *   - the **maintenance link**, deliberately — a `CREATE DATABASE … TEMPLATE` of a real schema can take
 *     longer than the tight per-statement capture budget, and the whole provisioning is bounded by
 *     `capture.shadow.timeout` instead. {@see ConnectionMaintenanceGateway} states this at its own head.
 *   - the **template connection**, which replays a whole schema dump through `getPdo()->exec()`.
 *   - the **MySQL replay**, likewise a whole dump.
 *
 * The last two are unbounded for no stated reason, and that is a real gap rather than a decision. It is
 * recorded rather than closed here because binding them is a behavior change on the provisioning path —
 * a per-statement budget over a schema dump aborts a legitimately long replay — and the harm that gap
 * carries today is bounded by the guards around shadow mode: throwaway databases, a refusal to run
 * against a production target, and the overall `capture.shadow.timeout`.
 *
 * It reuses the ONE per-driver set-path, `SessionGuard::statementsFor()`, for the
 * statement and lock budgets rather than growing a second one, and adds only what
 * the shadow path needs on top:
 *
 *   - PostgreSQL: `idle_in_transaction_session_timeout` (a shadow run holds a
 *     transaction open across a whole migrate, so an idle transaction must not
 *     pin resources), and `application_name = 'sqlens'` so a DBA watching
 *     `pg_stat_activity` can see exactly what SQLens is doing.
 *   - MySQL: nothing extra — its two axes already cover the statement and the lock.
 *
 * All three axes derive from the single `capture.shadow.timeout` (seconds), which
 * the config validator has already refused to let be zero or unbounded, so the
 * defense can never be configured off.
 */
final readonly class ShadowSessionDefense
{
    private SessionGuard $sessionGuard;

    public function __construct(private int $timeoutSeconds)
    {
        $milliseconds = $this->timeoutSeconds * 1000;

        // The statement and lock budgets are the SAME two axes the capture session
        // guard sets — reused, not re-implemented — both bounded by the shadow
        // timeout.
        $this->sessionGuard = new SessionGuard([
            'statement_timeout' => $milliseconds,
            'lock_timeout' => $milliseconds,
        ]);
    }

    /**
     * Apply the defense to a connection and return the statements it ran, so a
     * caller can show the budgets in effect — a limit a user cannot see is one they
     * cannot trust.
     *
     * @return list<string>
     */
    #[RawSql(reason: 'the shadow session gets the same SET defenses as the real one; a builder cannot express SET, and a second mechanism here would let the two drift')]
    public function apply(Connection $connection): array
    {
        $statements = $this->statementsFor($connection->getDriverName());

        foreach ($statements as $statement) {
            $connection->statement($statement);
        }

        return $statements;
    }

    /**
     * The session statements for an engine — the shared statement/lock axes plus
     * the shadow-only additions.
     *
     * @return list<string>
     */
    public function statementsFor(string $driver): array
    {
        $statements = $this->sessionGuard->statementsFor($driver);

        if ($driver === 'pgsql') {
            $statements[] = sprintf('SET idle_in_transaction_session_timeout = %d', $this->timeoutSeconds * 1000);
            $statements[] = "SET application_name = 'sqlens'";
        }

        return $statements;
    }
}
