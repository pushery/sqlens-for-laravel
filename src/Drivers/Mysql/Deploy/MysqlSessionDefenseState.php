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
 * Moved out of `SessionDefenseAppliedCheck`, which asked it behind a driver branch. Everything below, including the
 * measurement that decided which lock settings to read, traveled with it, because it is the reason
 * the query says what it says.
 */
final readonly class MysqlSessionDefenseState implements ReadsSessionDefenseState
{
    /** @return array<string, int|null> */
    #[RawSql(reason: 'reads the session timeouts back through the server own variables, for the same reason the PostgreSQL half reads its settings')]
    public function timeoutsInForce(ReaderSession $session): array
    {
        // Both lock waits, each under its own name, and the two names are the whole correctness of
        // this method.
        //
        // MySQL has two lock-wait settings and they bound different things: `innodb_lock_wait_timeout`
        // covers ROW locks and defaults to 50, `lock_wait_timeout` covers METADATA locks, which a
        // catalog read takes too, and defaults to 31536000, a year. This package documents that
        // difference at length in MysqlTimeouts, for a rule that refuses to accept one as the other,
        // and the session defense sets both.
        //
        // They move independently. Measured against MySQL 8.4.10 —
        //
        //     fresh connection            lock_wait_timeout 31536000   innodb_… 50
        //     after SET innodb_… = 3      lock_wait_timeout 31536000   innodb_…  3
        //
        // — so a read of one says nothing about the other. This method used to read the row lock
        // alone and report it under the metadata lock's name, which left the metadata-lock bound the
        // defense sets read back by nobody, and showed an operator a name that meant something else
        // on their server.
        $row = $session->read(static fn (Connection $db): array => $db->select(
            'select @@session.max_execution_time as max_execution_time,'
            .' @@session.innodb_lock_wait_timeout as innodb_lock_wait_timeout,'
            .' @@session.lock_wait_timeout as lock_wait_timeout',
        ))[0] ?? null;

        if (! is_object($row)) {
            throw new PreflightStateUnreadable('the session answered nothing about its timeouts');
        }

        return [
            'max_execution_time' => SessionTimeoutValue::milliseconds($row, 'max_execution_time'),
            'innodb_lock_wait_timeout' => $this->fromSeconds(SessionTimeoutValue::milliseconds($row, 'innodb_lock_wait_timeout')),
            'lock_wait_timeout' => $this->fromSeconds(SessionTimeoutValue::milliseconds($row, 'lock_wait_timeout')),
        ];
    }

    /**
     * A lock wait in milliseconds, from the seconds MySQL keeps it in.
     *
     * Converted here rather than compared raw: a lock wait of 50 is fifty SECONDS, and read as
     * milliseconds it would look like the tightest bound in the run. A value that could not be read
     * stays null through the conversion, because zero means NO TIMEOUT on this engine.
     *
     * Written as an `if` rather than a ternary, like the version parse in the connection factory: a
     * bare `? null` arm is EXECUTED and still counted uncovered by the driver, so it shows up as a gap
     * no test can close. Spelled out, the measurement matches what runs.
     */
    private function fromSeconds(?int $seconds): ?int
    {
        if ($seconds === null) {
            return null;
        }

        return $seconds * 1_000;
    }
}
