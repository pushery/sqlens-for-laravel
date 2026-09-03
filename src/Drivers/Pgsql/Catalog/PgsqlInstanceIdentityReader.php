<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Catalog;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\InstanceIdentity;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Contracts\InstanceIdentityReader;
use Pushery\SQLens\Findings\UndeterminedReason;
use Throwable;

/**
 * Who this PostgreSQL server is, asked of the server.
 *
 * One statement, five facts, no catalog scan and no lock. It runs inside the session the catalog
 * reader already opened and sealed read-only, so it inherits every bound that session carries — it
 * builds no connection of its own, which is what keeps "the audit opens exactly one connection"
 * true rather than aspirational.
 *
 * ## The NULL that is not a failure
 *
 * `inet_server_addr()` returns NULL over a Unix socket. That is the ordinary shape of a local
 * PostgreSQL, not a degradation, and a reader that treated it as an error would turn every
 * developer's machine into a failed audit. It becomes a named `undetermined` for the host field
 * alone; the port, database, version and role are still answered.
 *
 * ## What it deliberately does not read
 *
 * `pg_is_in_recovery()` answers "does this instance accept writes", which is what changes an
 * audit's meaning — a replica has its own settings and its own view of the schema. How far behind
 * replication is, and who the primary is, live in `pg_stat_replication` and are a different
 * question for a different suite. Reading them here would put replication monitoring inside an
 * identity probe.
 */
final readonly class PgsqlInstanceIdentityReader implements InstanceIdentityReader
{
    public function __construct(private ReaderSession $session) {}

    #[RawSql(reason: 'reads the settings that identify an instance; a GUC is not a column and no builder can name one')]
    public function read(string $connection): InstanceIdentity
    {
        try {
            // Every field is read INSIDE the try, and there is deliberately no separate "no row
            // came back" branch: this statement selects constants, so a server that answered at all
            // answered with a row. A branch for the impossible case would be a guard that guards
            // nothing — and if a driver ever did return nothing, the property access raises and the
            // catch turns it into the same named undetermined, which is the right answer anyway.
            $row = $this->session->read(static fn (Connection $db): mixed => $db->selectOne(
                // host(), not `::text`. Measured on PostgreSQL 18: the cast renders the inet type
                // WITH its netmask — `127.0.0.1/32`, `::1/128` — which is a network, not a host. It
                // would reach the report header as the server's identity and would fail every
                // address comparison, including the pinned-host check, while looking almost right.
                'select host(inet_server_addr()) as host,'
            .' inet_server_port() as port,'
            .' current_database() as db,'
            .' current_setting(\'server_version\') as version,'
                .' pg_is_in_recovery() as in_recovery'
            ));

            $host = $this->text($row, 'host');
            $port = $this->int($row, 'port');
            $database = $this->text($row, 'db');
            $version = $this->text($row, 'version');
            $readOnly = $this->bool($row, 'in_recovery');
        } catch (Throwable) {
            // Never propagates. A failed identity probe is a named undetermined about the instance,
            // not an exception that takes down a run which could still have audited a schema.
            return InstanceIdentity::unavailable($connection, UndeterminedReason::CatalogReadFailed);
        }

        return InstanceIdentity::of(
            connection: $connection,
            host: $host,
            port: $port,
            database: $database,
            serverVersion: $version,
            readOnly: $readOnly,
            // A local socket has no address to report. Named rather than blank, so a reader can
            // tell "connected over a socket" from "the reading could not say".
            unavailable: $host === null ? ['host' => UndeterminedReason::ManagedDatabaseRestriction] : [],
        );
    }

    private function text(mixed $row, string $key): ?string
    {
        $value = is_object($row) ? ($row->{$key} ?? null) : null;

        return is_scalar($value) && (string) $value !== '' ? (string) $value : null;
    }

    private function int(mixed $row, string $key): ?int
    {
        $value = is_object($row) ? ($row->{$key} ?? null) : null;

        return is_numeric($value) ? (int) $value : null;
    }

    /**
     * A boolean the driver really gave, or null.
     *
     * PDO's pgsql driver hands back a PHP `bool` for a boolean column — measured, not assumed — so
     * there is deliberately no string arm accepting `'t'` and `'true'`. It would be a branch nothing
     * reaches, and if some future driver did return a string, null is the honest answer: "the role
     * could not be read" is reported as an undetermined field, where a mis-parsed `'f'` read as
     * truthy would silently call a replica writable.
     */
    private function bool(mixed $row, string $key): ?bool
    {
        $value = is_object($row) ? ($row->{$key} ?? null) : null;

        return is_bool($value) ? $value : null;
    }
}
