<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Shadow;

use Illuminate\Database\ConnectionResolverInterface;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Contracts\ReplicaProbe;

/**
 * Asks MySQL whether the connection is read-only: a replica sets `@@read_only`
 * (or `@@innodb_read_only`) so writes are refused. Either being on marks the
 * instance as one a database-creating mode must not run against.
 *
 * This is the one MySQL-specific query the replica check needs, kept in the
 * driver namespace so the neutral shadow captor stays engine-agnostic. It is a
 * read of two server variables and writes nothing.
 */
final readonly class MysqlReplicaProbe implements ReplicaProbe
{
    public function __construct(private ConnectionResolverInterface $connections) {}

    #[RawSql(reason: 'asks @@read_only, because writing to a replica is the one mistake the shadow harness must never make')]
    public function isReplica(string $connectionName): bool
    {
        $row = $this->connections->connection($connectionName)
            ->selectOne('select @@read_only as read_only, @@innodb_read_only as innodb_read_only');

        // Either flag being on marks the instance read-only — a replica sets
        // read_only, and innodb_read_only can be on independently, so both are
        // checked rather than trusting one. A non-object result (no row, which this
        // select cannot produce) is folded in as "not a replica".
        return is_object($row) && (
            filter_var($row->read_only ?? false, FILTER_VALIDATE_BOOLEAN)
            || filter_var($row->innodb_read_only ?? false, FILTER_VALIDATE_BOOLEAN)
        );
    }
}
