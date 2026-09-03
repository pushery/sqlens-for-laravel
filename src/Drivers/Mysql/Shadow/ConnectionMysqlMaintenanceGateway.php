<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Shadow;

use Illuminate\Database\ConnectionInterface;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Contracts\ShadowDatabaseCatalog;

/**
 * The real MySQL maintenance gateway: the concrete SQL behind the
 * {@see MysqlMaintenanceGateway} port, run against a connection attached to a
 * system schema (`information_schema`).
 *
 * The reads are ordinary catalog queries. The two DDL statements — `CREATE DATABASE`
 * and `DROP DATABASE` — cannot be parameterized (identifiers are not bind
 * parameters), so the database name is backtick-quoted here and the character set
 * and collation are validated against `[A-Za-z0-9_]` before being interpolated, so
 * a value read from the catalog can never carry SQL into the statement.
 */
final readonly class ConnectionMysqlMaintenanceGateway implements MysqlMaintenanceGateway, ShadowDatabaseCatalog
{
    private const string DEFAULT_CHARSET = 'utf8mb4';

    private const string DEFAULT_COLLATION = 'utf8mb4_unicode_ci';

    /**
     * The admin schema a maintenance link attaches to. MySQL needs a connection to
     * SOME schema to issue `CREATE`/`DROP DATABASE`, and it must not be the one being
     * created or dropped; `information_schema` is always present and read-only.
     */
    public const string MAINTENANCE_DATABASE = 'information_schema';

    public function __construct(private ConnectionInterface $maintenance) {}

    #[RawSql(reason: 'lists databases by name prefix so the shadow harness can find and reap its own leftovers; SHOW DATABASES has no builder form')]
    public function listDatabasesWithPrefix(string $prefix): array
    {
        // Filter by prefix in PHP: the prefix contains `_`, a LIKE wildcard, so
        // filtering here avoids escaping it and cannot over-match.
        $names = [];

        foreach ($this->maintenance->select('select schema_name as name from information_schema.schemata') as $row) {
            $schema = is_object($row) ? $row->name ?? null : null;

            if (is_string($schema) && str_starts_with($schema, $prefix)) {
                $names[] = $schema;
            }
        }

        // The catalog view has no inherent order; the contract says this list has one.
        sort($names);

        return $names;
    }

    #[RawSql(reason: 'asks the server which product it is, because MariaDB shares this driver key and answers differently to nearly everything after this point')]
    public function isMariaDb(): bool
    {
        $row = $this->maintenance->selectOne('select version() as version');
        $version = is_object($row) ? $this->stringValue($row->version ?? null) : '';

        return str_contains(strtolower($version), 'mariadb');
    }

    #[RawSql(reason: 'asks whether this account may create and drop a database before the harness tries, so a refusal is reported rather than discovered as a crash')]
    public function canCreateAndDropDatabases(): bool
    {
        // SHOW GRANTS returns one column per row whose NAME is "Grants for user@host",
        // so each value is read positionally rather than by a fixed key.
        $grants = [];

        foreach ($this->maintenance->select('show grants for current_user()') as $row) {
            $values = array_values((array) $row);
            $grants[] = $this->stringValue($values[0] ?? null);
        }

        return self::grantsAllowProvisioning($grants);
    }

    /**
     * Whether a set of `SHOW GRANTS` lines grants the create-and-drop-database
     * capability — a global `ALL PRIVILEGES`, or an explicit `CREATE` together with
     * `DROP`. Pure, so both the granted and the denied outcome are testable without a
     * second MySQL account.
     *
     * @param  list<string>  $grants
     */
    public static function grantsAllowProvisioning(array $grants): bool
    {
        foreach ($grants as $grant) {
            $grant = strtoupper($grant);

            if (str_contains($grant, 'ALL PRIVILEGES') || (str_contains($grant, 'CREATE') && str_contains($grant, 'DROP'))) {
                return true;
            }
        }

        return false;
    }

    #[RawSql(reason: 'asks information_schema whether the shadow database is already there; the schema catalog is not a model')]
    public function databaseExists(string $name): bool
    {
        return $this->maintenance->selectOne(
            'select schema_name from information_schema.schemata where schema_name = ?',
            [$name],
        ) !== null;
    }

    #[RawSql(reason: 'reads a database default character set so the shadow copy is created like its original, not like the server default')]
    public function characterSetOf(string $database): array
    {
        $row = $this->maintenance->selectOne(
            'select default_character_set_name as charset, default_collation_name as collation '
            .'from information_schema.schemata where schema_name = ?',
            [$database],
        );

        $charset = is_object($row) ? $this->stringValue($row->charset ?? null) : '';
        $collation = is_object($row) ? $this->stringValue($row->collation ?? null) : '';

        return [
            'charset' => $this->validIdentifier($charset) ? $charset : self::DEFAULT_CHARSET,
            'collation' => $this->validIdentifier($collation) ? $collation : self::DEFAULT_COLLATION,
        ];
    }

    #[RawSql(reason: 'CREATE DATABASE -- DDL, and the query builder has no verb for it')]
    public function createDatabase(string $shadow, string $charset, string $collation): void
    {
        // Defense in depth: the charset/collation come from the catalog, but they
        // reach a non-parameterizable position, so an unexpected value falls back to
        // a safe default rather than being interpolated raw.
        $charset = $this->validIdentifier($charset) ? $charset : self::DEFAULT_CHARSET;
        $collation = $this->validIdentifier($collation) ? $collation : self::DEFAULT_COLLATION;

        $this->maintenance->statement(sprintf(
            'CREATE DATABASE %s CHARACTER SET %s COLLATE %s',
            $this->quoteIdentifier($shadow),
            $charset,
            $collation,
        ));
    }

    #[RawSql(reason: 'DROP DATABASE -- DDL the builder cannot express, and the reason the name is built from this class own prefix rather than from anything a caller supplies')]
    public function dropDatabase(string $name): void
    {
        $this->maintenance->statement(sprintf('DROP DATABASE IF EXISTS %s', $this->quoteIdentifier($name)));
    }

    /** Whether a value is a bare identifier safe to interpolate into DDL. */
    private function validIdentifier(string $value): bool
    {
        return $value !== '' && preg_match('/^\w+$/', $value) === 1;
    }

    /** Backtick-quote an identifier, doubling any embedded backtick. */
    private function quoteIdentifier(string $identifier): string
    {
        return '`'.str_replace('`', '``', $identifier).'`';
    }

    /** A scalar catalog value as a string; anything non-scalar becomes empty. */
    private function stringValue(mixed $value): string
    {
        return is_scalar($value) ? (string) $value : '';
    }
}
