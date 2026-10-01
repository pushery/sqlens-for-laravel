<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Exceptions\ShadowProvisioningUndetermined;
use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * Refuses a connection into a throwaway database that reaches any other database.
 *
 * A connection into a template, a clone or a shadow is the source connection's configuration with
 * `database` swapped, and the swap is the only thing that keeps a replay, the migrations and a read
 * of the expected schema off the database they were copied from. Which database a session actually
 * lands in is decided by the server, after the framework, a proxy or a pooler have each had a say in
 * the name. So the server is asked, once, before the first statement, and an answer other than the
 * throwaway database stops the run as a collision: the connection reached a database it must not
 * touch.
 *
 * Only the engines that create throwaway databases are asked. Any other connection has no shadow to
 * protect and is let through unasked.
 */
final readonly class ShadowConnectionLatch
{
    /**
     * @throws ShadowProvisioningUndetermined when the server reports another database
     */
    #[RawSql(reason: 'asks the server which database the session landed in, because that answer, not the configuration, decides where the next statement runs')]
    public static function assertReaches(Connection $connection, string $database): void
    {
        $query = match ($connection->getDriverName()) {
            // Unqualified, as in SessionGuard: the call takes no arguments, so no function elsewhere
            // on the search path is a closer match than the catalog's, and a schema name here would
            // be engine vocabulary in the driver-neutral core.
            'pgsql' => 'select current_database() as name',
            'mysql', 'mariadb' => 'select database() as name',
            default => null,
        };

        if ($query === null) {
            return;
        }

        $row = $connection->selectOne($query);
        $reached = is_object($row) && isset($row->name) && is_string($row->name) ? $row->name : null;

        if ($reached !== $database) {
            throw new ShadowProvisioningUndetermined(UndeterminedReason::ShadowConnectionCollides, sprintf(
                'The connection built for the throwaway database "%s" reached %s, so nothing was run on it.',
                $database,
                $reached === null ? 'no database' : '"'.$reached.'"',
            ));
        }
    }
}
