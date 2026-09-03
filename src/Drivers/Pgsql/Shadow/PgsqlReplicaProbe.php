<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Shadow;

use Illuminate\Database\ConnectionResolverInterface;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Contracts\ReplicaProbe;

/**
 * Asks PostgreSQL whether the connection is a standby: `pg_is_in_recovery()`
 * returns true on a hot-standby replica and false on a primary.
 *
 * This is the one PostgreSQL-specific query the replica check needs, kept in the
 * driver namespace so the neutral shadow captor never has to know how the
 * question is spelled per engine. It is a read — a single boolean select — and
 * writes nothing.
 */
final readonly class PgsqlReplicaProbe implements ReplicaProbe
{
    public function __construct(private ConnectionResolverInterface $connections) {}

    #[RawSql(reason: 'asks pg_is_in_recovery(), because writing to a replica is the one mistake the shadow harness must never make')]
    public function isReplica(string $connectionName): bool
    {
        $row = $this->connections->connection($connectionName)
            ->selectOne('select pg_is_in_recovery() as in_recovery');

        // A boolean column comes back as a PHP bool or the string 't'/'f'/'1'/'0'
        // depending on the driver's casting; normalize either into a clean bool
        // rather than trusting one representation.
        $value = is_object($row) ? ($row->in_recovery ?? false) : false;

        return filter_var($value, FILTER_VALIDATE_BOOLEAN);
    }
}
