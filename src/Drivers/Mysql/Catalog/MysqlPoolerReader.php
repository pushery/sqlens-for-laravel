<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Catalog;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\PoolerReading;
use Pushery\SQLens\Contracts\PoolerReader;
use Throwable;

/**
 * The MySQL twin, and it is a real one rather than a courtesy.
 *
 * ProxySQL — and MaxScale, and RDS Proxy — multiplex client connections onto a smaller pool of
 * server connections exactly as PgBouncer does, with the same consequence: two statements can run on
 * two backends, so `@@hostname`, the session-versus-global distinction and SQLens' own session
 * timeouts stop meaning what the reading assumes they mean.
 *
 * The tells are MySQL's own. `CONNECTION_ID()` is the server-side thread id and plays the part
 * `pg_backend_pid()` plays on PostgreSQL; a user-defined session variable plays the part of the
 * custom GUC. Both measurements run OUTSIDE a transaction, for the same reason as there: within one
 * transaction a multiplexer is obliged to keep a single backend, so that is the one place the effect
 * cannot be seen.
 *
 * The conventional port differs — ProxySQL's default client port is 6033 — and, as on the other
 * engine, it never decides the verdict on its own.
 */
final readonly class MysqlPoolerReader implements PoolerReader
{
    /** The user variable the persistence probe sets. Session-scoped and nothing to do with any table. */
    private const string PROBE_VARIABLE = '@sqlens_pooler_probe';

    /** A constant value, because a random one would make two runs of an unchanged project differ. */
    private const string PROBE_VALUE = 'sqlens';

    /** Ports a MySQL-side multiplexer conventionally listens on (ProxySQL's client port). */
    private const array POOLER_PORTS = [6033];

    /** Host-name fragments that say somebody put a multiplexer there on purpose. */
    private const array POOLER_HOST_FRAGMENTS = ['proxysql', 'maxscale', 'proxy', 'pooler'];

    public function __construct(private Connection $connection) {}

    #[RawSql(reason: 'detects a connection pooler by setting a session variable and reading it back on what should be the same session; SET has no builder verb, and the probe only means anything as the same statement pair every time')]
    public function read(): PoolerReading
    {
        $convention = $this->conventionSignals();

        try {
            $first = $this->threadId();
            $second = $this->threadId();

            if ($first !== $second) {
                return PoolerReading::pooled([
                    sprintf('the server thread changed between two statements (%s then %s)', $first, $second),
                    ...$convention,
                ]);
            }

            $this->connection->statement(sprintf("set %s = '%s'", self::PROBE_VARIABLE, self::PROBE_VALUE));

            if ($this->probeVariable() !== self::PROBE_VALUE) {
                return PoolerReading::pooled([
                    'a session variable did not survive into the next statement',
                    ...$convention,
                ]);
            }
        } catch (Throwable $error) {
            return PoolerReading::undetermined([
                'the probe could not run: '.$error->getMessage(),
                ...$convention,
            ]);
        }

        return PoolerReading::direct($convention);
    }

    /** @return list<string> */
    private function conventionSignals(): array
    {
        $signals = [];
        $port = $this->connection->getConfig('port');
        $host = $this->connection->getConfig('host');

        if (is_numeric($port) && in_array((int) $port, self::POOLER_PORTS, true)) {
            $signals[] = sprintf('the port %s is a pooler convention', (int) $port);
        }

        foreach (self::POOLER_HOST_FRAGMENTS as $fragment) {
            if (is_string($host) && str_contains(strtolower($host), $fragment)) {
                $signals[] = sprintf('the host name contains "%s"', $fragment);
            }
        }

        return $signals;
    }

    #[RawSql(reason: 'asks connection_id() -- a server function, and the value the pooler probe compares against')]
    private function threadId(): int
    {
        /** @var object{id?: int|string|null}|null $row */
        $row = $this->connection->selectOne('select connection_id() as id');

        return is_object($row) ? (int) ($row->id ?? 0) : 0;
    }

    #[RawSql(reason: 'reads back the session variable the probe set; the name is this class own constant, so the statement is entirely the package own text')]
    private function probeVariable(): ?string
    {
        /** @var object{value?: string|null}|null $row */
        $row = $this->connection->selectOne(sprintf('select %s as value', self::PROBE_VARIABLE));

        return is_object($row) && is_string($row->value ?? null) ? $row->value : null;
    }
}
