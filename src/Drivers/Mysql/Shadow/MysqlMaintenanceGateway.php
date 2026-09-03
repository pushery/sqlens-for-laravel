<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Shadow;

/**
 * The catalog reads and database DDL the MySQL shadow provisioner needs from a
 * maintenance connection (attached to a system schema such as `information_schema`).
 *
 * As on the PostgreSQL side, it is a port so the provisioner's ORCHESTRATION — the
 * MariaDB refusal, the privilege and collision preconditions, and the create/replay/
 * drop sequence — is testable against a fake, while the concrete gateway carries the
 * real SQL and is proven against a live `mysql:8.4`. No `CREATE DATABASE` string
 * lives in the provisioner; no undetermined-reason logic lives here.
 */
interface MysqlMaintenanceGateway
{
    /**
     * Whether the server is MariaDB rather than MySQL. MariaDB is a declared
     * non-goal (its dump format and version-gated comments diverge), so it is
     * refused as a named unsupported result, never routed through the MySQL path.
     */
    public function isMariaDb(): bool;

    /**
     * Whether the current user can both create and drop databases — the two
     * privileges the shadow lifecycle needs. Checked before any `CREATE DATABASE`,
     * so a user who cannot provision produces a named result, not a mid-run error.
     */
    public function canCreateAndDropDatabases(): bool;

    /** Whether a schema named $name already exists in `information_schema.SCHEMATA`. */
    public function databaseExists(string $name): bool;

    /**
     * The default character set and collation of $database, read from
     * `information_schema.SCHEMATA` so the clone inherits the source's — MySQL has
     * no `TEMPLATE`, so the character set is carried explicitly instead of implicitly.
     *
     * @return array{charset: string, collation: string}
     */
    public function characterSetOf(string $database): array;

    /** Create $shadow with the given character set and collation. */
    public function createDatabase(string $shadow, string $charset, string $collation): void;

    /**
     * Drop $name with `DROP DATABASE IF EXISTS` — idempotent, so a name already gone
     * (a teardown that runs twice, or after a failed replay) is not an error.
     */
    public function dropDatabase(string $name): void;
}
