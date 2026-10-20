<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Shadow;

use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\ConnectionResolverInterface;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Contracts\ReplicaProbe;
use Throwable;

/**
 * Asks MySQL whether the connection is a replica: one that is read-only (`@@read_only` or
 * `@@innodb_read_only`), or one that replicates from a source over a channel of its own. Either
 * marks the instance as one a database-creating mode must not run against.
 *
 * The channel is read because MySQL does not set `read_only` on a replica by itself; the operator
 * does. A replica left writable accepts the writes provisioning makes, and in a GTID topology they
 * become transactions the replica holds and its source does not. Its channel is a row in
 * `performance_schema.replication_connection_configuration`. The two channels group replication
 * keeps on every member, the writable primary included, are not counted: a secondary of a group is
 * read-only already, and the primary is the server provisioning belongs on.
 *
 * Reading that table needs `SELECT` on it, which an application account usually lacks. Such an
 * account is answered by the read-only flags alone, as before the channel was read, rather than
 * refused: a refusal would stop shadow mode for every account without the grant, on primaries as
 * much as on replicas. The shadow-mode documentation names the grant that makes the check complete.
 *
 * This is the one MySQL-specific query set the replica check needs, kept in the driver namespace so
 * the neutral shadow captor stays engine-agnostic. It reads server variables and one table, and
 * writes nothing.
 */
final readonly class MysqlReplicaProbe implements ReplicaProbe
{
    public function __construct(private ConnectionResolverInterface $connections) {}

    #[RawSql(reason: 'asks @@read_only, because writing to a replica is the one mistake the shadow harness must never make')]
    public function isReplica(string $connectionName): bool
    {
        // Through the WRITE side. On a connection with a read/write split the read side is a
        // replica by design, and the question is about the server provisioning writes to.
        $connection = $this->connections->connection($connectionName);
        $row = $connection->selectOne('select @@read_only as read_only, @@innodb_read_only as innodb_read_only', [], false);

        // Either flag being on marks the instance read-only — a replica sets
        // read_only, and innodb_read_only can be on independently, so both are
        // checked rather than trusting one. A non-object result (no row, which this
        // select cannot produce) is folded in as "not read-only".
        $readOnly = is_object($row) && (
            filter_var($row->read_only ?? false, FILTER_VALIDATE_BOOLEAN)
            || filter_var($row->innodb_read_only ?? false, FILTER_VALIDATE_BOOLEAN)
        );

        return $readOnly || $this->replicatesOverAChannel($connection);
    }

    /**
     * Whether the server has a replication channel other than group replication's, as far as the
     * account may read it; false where it may not, which leaves the answer to the read-only flags.
     */
    #[RawSql(reason: 'reads performance_schema.replication_connection_configuration, the channel a replica left writable still carries')]
    private function replicatesOverAChannel(ConnectionInterface $connection): bool
    {
        try {
            $row = $connection->selectOne(
                'select count(*) as channels from performance_schema.replication_connection_configuration'
                ." where channel_name not in ('group_replication_applier', 'group_replication_recovery')",
                [],
                false,
            );
        } catch (Throwable) {
            // Not readable is the ordinary case for an application account. Not an error: the
            // read-only flags still answer, and the documentation names the grant.
            return false;
        }

        $channels = is_object($row) ? $row->channels ?? null : null;

        return is_numeric($channels) && (int) $channels > 0;
    }
}
