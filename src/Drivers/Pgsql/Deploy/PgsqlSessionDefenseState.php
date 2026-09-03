<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Deploy;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Contracts\ReadsSessionDefenseState;
use Pushery\SQLens\Deploy\Checks\PreflightStateUnreadable;
use Pushery\SQLens\Deploy\SessionTimeoutValue;

/**
 * PostgreSQL's read-back of the session timeouts this run set.
 *
 * Moved out of `SessionDefenseAppliedCheck`, which asked it behind a driver branch.
 * The query, the keys and the failure mode are the ones that were already there; what changed is
 * who knows them.
 */
final readonly class PgsqlSessionDefenseState implements ReadsSessionDefenseState
{
    /** @return array<string, int|null> */
    #[RawSql(reason: 'reads the timeouts this run set back through current_setting(); a builder cannot ask for a GUC, and reading them back is how the check proves the defense applied')]
    public function timeoutsInForce(ReaderSession $session): array
    {
        $row = $session->read(static fn (Connection $db): array => $db->select(
            "select current_setting('statement_timeout') as statement_timeout,"
            ." current_setting('lock_timeout') as lock_timeout",
        ))[0] ?? null;

        if (! is_object($row)) {
            throw new PreflightStateUnreadable('the session answered nothing about its timeouts');
        }

        return [
            'statement_timeout' => SessionTimeoutValue::milliseconds($row, 'statement_timeout'),
            'lock_timeout' => SessionTimeoutValue::milliseconds($row, 'lock_timeout'),
        ];
    }
}
