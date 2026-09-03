<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Deploy;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Contracts\ReadsSessionDefenseState;
use Pushery\SQLens\Deploy\Checks\PreflightStateUnreadable;
use Pushery\SQLens\Deploy\SessionTimeoutValue;

/**
 * MySQL's read-back of the session timeouts this run set.
 *
 * Moved out of `SessionDefenseAppliedCheck`, which asked it behind a driver branch. Everything below — including the
 * measurement that decided which lock setting to read — traveled with it, because it is the reason
 * the query says what it says.
 */
final readonly class MysqlSessionDefenseState implements ReadsSessionDefenseState
{
    /** @return array<string, int|null> */
    #[RawSql(reason: 'reads the session timeouts back through the server own variables, for the same reason the PostgreSQL half reads its settings')]
    public function timeoutsInForce(ReaderSession $session): array
    {
        // `innodb_lock_wait_timeout`, and the choice is the whole correctness of this method.
        //
        // MySQL has two lock-wait settings and they bound different things: `lock_wait_timeout`
        // covers METADATA locks (what a DDL statement waits on) and defaults to 31536000 — a year —
        // while `innodb_lock_wait_timeout` covers ROW locks and defaults to 50. This package
        // documents that difference at length in MysqlTimeouts, for a rule that refuses to accept
        // one as the other.
        //
        // The check used to read `lock_wait_timeout`, which MysqlSessionDefense never touches. That
        // is not merely a wrong number: it is a CONSTANT. Measured against MySQL 8.4.10 —
        //
        //     fresh connection            lock_wait_timeout 31536000   innodb_… 50
        //     after SET innodb_… = 3      lock_wait_timeout 31536000   innodb_…  3
        //
        // — so the arm reported the defense as not applied on every MySQL run, and, worse, could not
        // have gone red if the defense had genuinely failed. A check reading a value nothing writes
        // is a silent green wearing a red coat.
        //
        // Which setting is RIGHT follows from what this session does: it reads catalogs and runs no
        // DDL, so it waits on row locks, not metadata locks. The defense is correct; the reader was
        // not. Setting `lock_wait_timeout` as well — to make the old read pass — would have been the
        // repair at the symptom, and would blur a boundary this package defends elsewhere.
        $row = $session->read(static fn (Connection $db): array => $db->select(
            'select @@session.max_execution_time as max_execution_time,'
            .' @@session.innodb_lock_wait_timeout as lock_wait_timeout',
        ))[0] ?? null;

        if (! is_object($row)) {
            throw new PreflightStateUnreadable('the session answered nothing about its timeouts');
        }

        // Seconds on the lock wait, and the unit difference is the reason it is converted here
        // rather than compared raw: a lock wait of 50 is fifty SECONDS, and read as milliseconds it
        // would look like the tightest bound in the run.
        //
        // Written as an `if` rather than a ternary, like the version parse in the connection
        // factory: a bare `? null` arm is EXECUTED and still counted uncovered by the driver, so it
        // shows up as a gap no test can close. Spelled out, the measurement matches what runs.
        $seconds = SessionTimeoutValue::milliseconds($row, 'lock_wait_timeout');
        $lockWaitMs = null;

        if ($seconds !== null) {
            $lockWaitMs = $seconds * 1_000;
        }

        return [
            'max_execution_time' => SessionTimeoutValue::milliseconds($row, 'max_execution_time'),
            // The KEY keeps the generic name while the VALUE now comes from
            // `innodb_lock_wait_timeout`, and that mismatch is deliberate rather than overlooked:
            // the key is the cross-engine name for "how long this session waits for a lock", and
            // PostgreSQL answers it from `lock_timeout`. Renaming it per engine would push the
            // engine difference into every consumer of this array. On MySQL it therefore names the
            // ROW-lock bound — which is the one that applies to a reader.
            'lock_wait_timeout' => $lockWaitMs,
        ];
    }
}
