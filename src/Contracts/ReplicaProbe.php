<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

/**
 * Answers whether the target connection is a read replica — the one live check a
 * database-creating mode makes before it touches the instance.
 *
 * The question is engine-specific (PostgreSQL asks `pg_is_in_recovery()`, MySQL
 * reads `@@read_only` / `@@innodb_read_only`), so it lives behind this seam and
 * the concrete probes hold the query. The shadow captor asks only "is this a
 * replica?" and turns a yes into a named undetermined, never a run — a replica
 * has a different state than its primary, and provisioning against it would
 * describe the wrong database.
 *
 * A probe is a read: it selects a status flag and nothing more. It writes
 * nothing and takes no lock, like every other connection SQLens opens.
 */
interface ReplicaProbe
{
    /**
     * Whether the named connection is a read replica. The probe runs its
     * engine-specific status query against that connection.
     */
    public function isReplica(string $connectionName): bool;
}
