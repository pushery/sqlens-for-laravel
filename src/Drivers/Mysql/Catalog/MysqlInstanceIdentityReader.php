<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Catalog;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\InstanceIdentity;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Contracts\InstanceIdentityReader;
use Pushery\SQLens\Findings\UndeterminedReason;
use Throwable;

/**
 * Who this MySQL server is, asked of the server.
 *
 * The PostgreSQL sister's shape, with MySQL's own vocabulary and one difference worth stating:
 * `@@hostname` is the server's OWN name, not the host the client dialled. Measured — a server
 * reached at `127.0.0.1` reports its machine name. That is the right answer to "which machine am I
 * on" and the wrong answer to "did I reach the host I configured", so a consumer comparing it
 * against a configured host has to know which question it asked. Recorded rather than reconciled
 * here: reconciling them is a finding somebody else makes, not a fact this reader has.
 *
 * ## The role indication
 *
 * `read_only` and `super_read_only` together answer "does this instance accept writes". A replica
 * has its own variables and its own view of the schema, so an audit that did not know it was
 * talking to one would report settings the primary does not have. `super_read_only` is read as well
 * because `read_only` alone does not hold a `SUPER` user back, and an audit connecting with an
 * elevated account would otherwise read a replica as writable.
 *
 * Deliberately NOT the replication views: how far behind a replica is, and who its primary is, are
 * a different question for a different suite.
 */
final readonly class MysqlInstanceIdentityReader implements InstanceIdentityReader
{
    public function __construct(private ReaderSession $session) {}

    #[RawSql(reason: 'reads the server variables that identify an instance; @@-variables are not columns and no builder can name them')]
    public function read(string $connection): InstanceIdentity
    {
        try {
            // Every field is read INSIDE the try, and there is deliberately no separate "no row
            // came back" branch: this statement selects constants, so a server that answered at all
            // answered with a row. A branch for the impossible case would be a guard that guards
            // nothing — and if a driver ever did return nothing, the property access raises and the
            // catch turns it into the same named undetermined, which is the right answer anyway.
            $row = $this->session->read(static fn (Connection $db): mixed => $db->selectOne(
                'select @@hostname as host,'
                .' @@port as port,'
                .' database() as db,'
                .' version() as version,'
                .' @@read_only as read_only,'
                .' @@super_read_only as super_read_only'
            ));

            $host = $this->text($row, 'host');
            $port = $this->int($row, 'port');
            $database = $this->text($row, 'db');
            $version = $this->text($row, 'version');
            $readOnly = $this->truthy($row, 'read_only') || $this->truthy($row, 'super_read_only');
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
            // Empty, and that is not an oversight. On MySQL every one of these five answers on any
            // reachable server: `@@hostname` is always set, `database()` is null only for a session
            // with no default schema — which Laravel cannot produce, because a connection without a
            // database fails to open at all. So the only way a field goes missing here is the way
            // they ALL go missing, which the catch above already reports. PostgreSQL is different
            // and its sister carries a per-field case for exactly that reason: `inet_server_addr()`
            // really is null on an ordinary local socket.
            unavailable: [],
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

    private function truthy(mixed $row, string $key): bool
    {
        $value = is_object($row) ? ($row->{$key} ?? null) : null;

        return is_scalar($value) && in_array((string) $value, ['1', 'ON', 'on', 'true'], true);
    }
}
