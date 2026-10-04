<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Shadow;

use Illuminate\Database\ConnectionInterface;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Contracts\ShadowDatabaseCatalog;
use Pushery\SQLens\Exceptions\ShadowProvisioningUndetermined;
use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * The real PostgreSQL maintenance gateway: the concrete SQL behind the
 * {@see MaintenanceGateway} port, run against a connection attached to an admin
 * database (`postgres`), never the template being cloned.
 *
 * The reads are ordinary parameterized selects. The two DDL statements —
 * `CREATE DATABASE … TEMPLATE` and `DROP DATABASE … WITH (FORCE)` — cannot be
 * parameterized (identifiers are not bind parameters), so the database names are
 * quoted here with the standard double-quote-doubling escape. The shadow name is
 * generated from `[a-z0-9_]` and the template name comes from configuration;
 * quoting is defense in depth, not the only barrier.
 *
 * No session timeout is set on this connection: a `CREATE DATABASE … TEMPLATE` of
 * a real schema can take longer than the tight per-statement capture budget, and
 * the whole provisioning is instead bounded by `capture.shadow.timeout`. This
 * connection is a maintenance link, not a capture session.
 */
final readonly class ConnectionMaintenanceGateway implements MaintenanceGateway, ShadowDatabaseCatalog
{
    /**
     * The admin database a maintenance link attaches to. PostgreSQL requires a
     * connection to SOME database to issue `CREATE`/`DROP DATABASE`, and it must not
     * be the one being created, dropped, or cloned — `postgres` is the conventional
     * always-present admin database for exactly this.
     */
    public const string MAINTENANCE_DATABASE = 'postgres';

    /**
     * @param  ConnectionInterface|null  $source  the database the shadow stands in for. Given, a new
     *                                            template takes its encoding and locale, see
     *                                            {@see createEmptyDatabase()}.
     */
    public function __construct(
        private ConnectionInterface $maintenance,
        private ?ConnectionInterface $source = null,
    ) {}

    #[RawSql(reason: 'lists databases by name prefix so the shadow harness can find and reap its own leftovers; pg_database is not a model')]
    public function listDatabasesWithPrefix(string $prefix): array
    {
        // Fetch every database and filter by prefix in PHP: the prefix contains `_`,
        // a LIKE wildcard, so filtering here avoids escaping it and cannot over-match.
        $names = [];

        foreach ($this->maintenance->select('select datname as name from pg_database') as $row) {
            $datname = is_object($row) ? $row->name ?? null : null;

            if (is_string($datname) && str_starts_with($datname, $prefix)) {
                $names[] = $datname;
            }
        }

        // The catalog view has no inherent order; the contract says this list has one.
        sort($names);

        return $names;
    }

    #[RawSql(reason: 'asks whether this role may create a database before the harness tries, so a refusal is reported rather than discovered as a crash')]
    public function canCreateDatabase(): bool
    {
        // A superuser can always create databases even without the CREATEDB
        // attribute set explicitly, so both are accepted.
        $row = $this->maintenance->selectOne(
            'select (rolcreatedb or rolsuper) as allowed from pg_roles where rolname = current_user'
        );

        $value = is_object($row) ? ($row->allowed ?? false) : false;

        return filter_var($value, FILTER_VALIDATE_BOOLEAN);
    }

    #[RawSql(reason: 'counts backends on the template database, because CREATE DATABASE from a template fails while anyone is connected to it')]
    public function activeConnectionCount(string $database): int
    {
        // Exclude our own backend: the maintenance connection is attached to the
        // admin database, not the template, but excluding self keeps the count
        // honest regardless of where this connection sits.
        $row = $this->maintenance->selectOne(
            'select pg_catalog.count(*) as total from pg_stat_activity where datname = ? and pid <> pg_catalog.pg_backend_pid()',
            [$database],
        );

        $total = is_object($row) ? $row->total ?? 0 : 0;

        return is_numeric($total) ? (int) $total : 0;
    }

    #[RawSql(reason: 'names who is connected, so the refusal above says WHO is in the way instead of only that somebody is')]
    public function describeActiveConnections(string $database): array
    {
        // The same population the count reads, so the two can never disagree about who is
        // there — same predicate, same exclusion of this backend. A second, subtly different
        // WHERE clause is how a refusal starts naming sessions the decision did not count.
        //
        // `query` is absent by design; see the interface. `state` can be null for a backend
        // that has not run anything yet, so it is coalesced rather than dropped — "unknown"
        // is still an answer, and a missing row would be worse than a vague one.
        $rows = $this->maintenance->select(
            'select pid, coalesce(application_name, \'\') as application_name,'
            .' coalesce(state, \'unknown\') as state,'
            .' coalesce(pg_catalog.to_char(backend_start, \'YYYY-MM-DD"T"HH24:MI:SSOF\'), \'unknown\') as backend_start'
            .' from pg_stat_activity where datname = ? and pid <> pg_catalog.pg_backend_pid()'
            .' order by pid',
            [$database],
        );

        $described = [];

        foreach ($rows as $row) {
            if (! is_object($row)) {
                continue;
            }

            $described[] = [
                'pid' => is_numeric($row->pid ?? null) ? (int) $row->pid : 0,
                'application_name' => is_string($row->application_name ?? null) ? $row->application_name : '',
                'state' => is_string($row->state ?? null) ? $row->state : 'unknown',
                'backend_start' => is_string($row->backend_start ?? null) ? $row->backend_start : 'unknown',
            ];
        }

        return $described;
    }

    #[RawSql(reason: 'asks pg_database whether the shadow database is already there')]
    public function databaseExists(string $name): bool
    {
        return $this->maintenance->selectOne('select 1 as present from pg_database where datname = ?', [$name]) !== null;
    }

    #[RawSql(
        reason: 'CREATE DATABASE -- DDL, and the query builder has no verb for it',
        interpolation: 'the name is built from the prefix this class owns, and the encoding and locale are read from pg_database and written as quoted literals; no engine binds either',
    )]
    public function createEmptyDatabase(string $name): void
    {
        // template0, never template1: template1 is the default source and a site may
        // have added objects to it, so it is not guaranteed to be pristine. template0
        // is, and PostgreSQL keeps it that way.
        //
        // Its encoding and locale are the cluster's, though, and a project's database may have
        // others. Measured on PostgreSQL 18: a LATIN1 database refuses a `€` its UTF8 shadow took,
        // so the shadow passed a migration the real database would fail, and an ICU database got a
        // libc shadow. So the template takes the source database's when the gateway knows it.
        $this->maintenance->statement(sprintf(
            'CREATE DATABASE %s TEMPLATE template0%s',
            $this->quoteIdentifier($name),
            $this->source instanceof ConnectionInterface ? $this->localeOf($this->source) : '',
        ));
    }

    /**
     * The clauses that give a new database the encoding, locale provider and locale of $source, read
     * from its own row in `pg_database`, ICU rules included.
     *
     * @throws ShadowProvisioningUndetermined when the source does not describe itself
     */
    #[RawSql(reason: 'reads the encoding and locale of the database the shadow stands in for from pg_database; a catalog row, not a model')]
    private function localeOf(ConnectionInterface $source): string
    {
        $row = $source->selectOne(
            'select pg_catalog.pg_encoding_to_char(encoding) as encoding, datlocprovider as provider, datcollate, '
            .'datctype, datlocale, daticurules from pg_catalog.pg_database where datname = pg_catalog.current_database()',
        );

        // PostgreSQL always has a row for the database a session is in. A driver answering without
        // one leaves the template's rules unknown, and a shadow under unknown rules is not built.
        if (! is_object($row)) {
            throw new ShadowProvisioningUndetermined(UndeterminedReason::ShadowTemplateBuildFailed);
        }

        $clauses = sprintf(
            ' ENCODING %s LC_COLLATE %s LC_CTYPE %s',
            $this->literal($row, 'encoding'),
            $this->literal($row, 'datcollate'),
            $this->literal($row, 'datctype'),
        );

        return $clauses.match ($this->text($row, 'provider')) {
            'i' => ' LOCALE_PROVIDER icu ICU_LOCALE '.$this->literal($row, 'datlocale').($this->text($row, 'daticurules') === '' ? '' : ' ICU_RULES '.$this->literal($row, 'daticurules')),
            'b' => ' LOCALE_PROVIDER builtin BUILTIN_LOCALE '.$this->literal($row, 'datlocale'),
            default => ' LOCALE_PROVIDER libc',
        };
    }

    /** A column of a catalog row as a string literal, its quotes doubled. */
    private function literal(object $row, string $key): string
    {
        return "'".str_replace("'", "''", $this->text($row, $key))."'";
    }

    /** A column of a catalog row as text, or the empty string when it is null. */
    private function text(object $row, string $key): string
    {
        $value = $row->{$key} ?? null;

        return is_scalar($value) ? (string) $value : '';
    }

    #[RawSql(
        reason: 'CREATE DATABASE ... TEMPLATE -- DDL with a clause no builder models, and the fast path the shadow harness stands on',
        interpolation: 'both names are built from the prefix this class owns; no engine binds a database name',
    )]
    public function createDatabaseFromTemplate(string $shadow, string $template): void
    {
        $this->maintenance->statement(sprintf(
            'CREATE DATABASE %s TEMPLATE %s',
            $this->quoteIdentifier($shadow),
            $this->quoteIdentifier($template),
        ));
    }

    #[RawSql(
        reason: 'DROP DATABASE -- DDL the builder cannot express, and the reason the name is built from this class own prefix rather than from anything a caller supplies',
        interpolation: 'the name goes through quoteIdentifier(); no engine binds a database name',
    )]
    public function dropDatabase(string $name): void
    {
        $this->maintenance->statement(sprintf(
            'DROP DATABASE IF EXISTS %s WITH (FORCE)',
            $this->quoteIdentifier($name),
        ));
    }

    /** Double-quote an identifier, doubling any embedded double quote. */
    private function quoteIdentifier(string $identifier): string
    {
        return '"'.str_replace('"', '""', $identifier).'"';
    }
}
