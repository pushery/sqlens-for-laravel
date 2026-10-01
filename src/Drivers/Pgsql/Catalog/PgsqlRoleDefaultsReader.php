<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Catalog;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\ReaderSession;
use Throwable;

/**
 * The defaults stored per role and per database, read from `pg_db_role_setting`, and the role this
 * session logged in as.
 *
 * Two statements over the catalog, no lock, inside the session the preflight already sealed. The
 * table is readable to a role that holds nothing but `CONNECT`, measured on PostgreSQL 18.4, so a
 * preflight account needs no grant for it.
 *
 * `session_user` rather than `current_user`: a stored default takes effect when a role logs in, and
 * a later `SET ROLE` does not apply the defaults of the role it switches to.
 */
final readonly class PgsqlRoleDefaultsReader
{
    public function __construct(private ReaderSession $session) {}

    #[RawSql(reason: 'reads pg_db_role_setting; the defaults ALTER ROLE and ALTER DATABASE store have no other representation, and which role is logged in decides which of them apply')]
    public function read(): RoleDefaults
    {
        try {
            /** @var array<int, object> $rows */
            $rows = $this->session->read(static fn (Connection $db): array => $db->select(
                'select s.setdatabase <> 0 as this_database, r.rolname as role, c.entry'
                .' from pg_catalog.pg_db_role_setting s'
                .' cross join lateral pg_catalog.unnest(s.setconfig) as c(entry)'
                .' left join pg_catalog.pg_roles r on r.oid = s.setrole'
                .' where s.setdatabase in (0, (select d.oid from pg_catalog.pg_database d where d.datname = pg_catalog.current_database()))'
            ));

            $reader = $this->session->read(static fn (Connection $db): mixed => $db->selectOne('select session_user as name'));
        } catch (Throwable) {
            return RoleDefaults::unread();
        }

        $entries = [];

        foreach ($rows as $row) {
            // `name=value`, split at the first `=`: a value may hold one of its own, a name never does.
            [$name, $value] = explode('=', is_scalar($row->entry ?? null) ? (string) $row->entry : '', 2) + ['', ''];
            $role = $row->role ?? null;

            $entries[] = [
                'thisDatabase' => ($row->this_database ?? false) === true,
                'role' => is_scalar($role) ? (string) $role : null,
                'name' => $name,
                'value' => $value,
            ];
        }

        $name = is_object($reader) ? ($reader->name ?? null) : null;

        return is_scalar($name) ? RoleDefaults::of((string) $name, $entries) : RoleDefaults::unread();
    }
}
