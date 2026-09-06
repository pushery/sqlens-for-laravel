<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Catalog;

use Closure;
use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\PoolerReading;
use Pushery\SQLens\Catalog\SessionBudget;
use Pushery\SQLens\Contracts\PoolerReader;
use Throwable;

/**
 * The PostgreSQL transaction-pooling heuristic — two measurements and one convention.
 *
 * ## Why it is a heuristic and says so
 *
 * A pooler is transparent by design. There is no `am_i_behind_pgbouncer()` to call, so this reads
 * tells and reports what it saw rather than an authority's answer. Both measurements run OUTSIDE a
 * transaction, which is the whole trick: transaction pooling guarantees one backend per
 * transaction, so anything measured inside one is measured in the one place the effect is
 * suppressed.
 *
 * **The backend process.** `pg_backend_pid()` twice, as two separate statements. A direct
 * connection answers the same number both times; transaction pooling can hand the second statement
 * a different server connection. A change is conclusive evidence of multiplexing — nothing else
 * produces it.
 *
 * **Session persistence.** A custom GUC is set and read back in a following statement. On a direct
 * connection it survives; behind a transaction pooler the read may land on a backend that never saw
 * the `SET`. `sqlens.probe` is namespaced, which PostgreSQL permits for exactly this kind of use,
 * and is a session variable — nothing in any database is touched.
 *
 * Neither measurement is a false-positive risk: a stable pid and a surviving setting are what a
 * direct connection produces, and neither can be produced by multiplexing *on the statement that
 * observed it*. The reverse is not true — a pooled connection under no load may hand back the same
 * backend twice — which is why the two run together and why a *negative* result is the weaker one.
 *
 * ## The port is a convention, not evidence
 *
 * `6432` is PgBouncer's default and a host named `pooler` says what somebody intended. Neither
 * proves anything: a direct server can listen on 6432, and a pooler can sit on 5432. So the
 * convention never decides the verdict on its own. It is recorded as a signal, and it matters in
 * exactly one case — when the measurements could not run, where a config that says "pooler" is the
 * difference between "could not tell" and "could not tell, and there is reason to worry".
 */
final readonly class PgsqlPoolerReader implements PoolerReader
{
    /** The custom GUC the persistence probe sets. Namespaced, so it can never collide with a real one. */
    private const string PROBE_SETTING = 'sqlens.pooler_probe';

    /** The value it is set to — a constant, because a random one would make two runs differ. */
    private const string PROBE_VALUE = 'sqlens';

    /** Ports a transaction pooler conventionally listens on. */
    private const array POOLER_PORTS = [6432];

    /** Host-name fragments that say somebody put a pooler there on purpose. */
    private const array POOLER_HOST_FRAGMENTS = ['pgbouncer', 'pooler'];

    public function __construct(private Connection $connection, private ?SessionBudget $budget = null) {}

    #[RawSql(reason: 'detects a connection pooler by setting a session setting and reading it back on what should be the same backend; SET has no builder verb')]
    public function read(): PoolerReading
    {
        $convention = $this->conventionSignals();

        // Declared before the try so the finally below can always call it, including on a throw
        // from the bounding statement itself.
        $restore = static function (): void {};

        try {
            // Bounded BEFORE the first probe statement, and this is the only place in an audit
            // where that has to be arranged by hand: every other read runs inside ReaderSession,
            // which seals and bounds the session on the way in. The pooler probe cannot use it —
            // pooling is invisible inside a transaction, which is exactly what ReaderSession opens
            // — so these statements were the four an audit sent a production server unbounded.
            //
            // Each of them is constant-time, so the bound is not about a slow query: it is about
            // never holding a connection open with no limit at all, which is the promise, and about
            // a pooler that accepts the connection and then never answers.
            $restore = $this->bound();

            // Two SEPARATE statements, outside any transaction. Inside one, a transaction pooler
            // behaves exactly like a direct connection — which is the guarantee it exists to give.
            $first = $this->backendPid();
            $second = $this->backendPid();

            if ($first !== $second) {
                return PoolerReading::pooled([
                    sprintf('the backend process changed between two statements (%s then %s)', $first, $second),
                    ...$convention,
                ]);
            }

            $this->connection->statement(sprintf("set %s = '%s'", self::PROBE_SETTING, self::PROBE_VALUE));
            $survived = $this->probeSetting();

            if ($survived !== self::PROBE_VALUE) {
                return PoolerReading::pooled([
                    'a session setting did not survive into the next statement',
                    ...$convention,
                ]);
            }
        } catch (Throwable $error) {
            // Never propagates. The schema is the same on every backend, so a run that could not
            // establish the topology can still audit one — it just may not speak about the instance.
            return PoolerReading::undetermined([
                'the probe could not run: '.$error->getMessage(),
                ...$convention,
            ]);
        } finally {
            // The connection is the HOST APPLICATION's, so the bound is put back on every path —
            // including the two that return early. A timeout left behind would make an unrelated
            // query fail later for a reason the application never chose.
            $restore();
        }

        // Measured direct. The convention travels anyway when it disagrees, because a reader
        // looking at a report from a host named `pooler` deserves to see that SQLens noticed and
        // measured it rather than to wonder whether it looked.
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

    /**
     * Bound this connection for the probe, and hand back the undo.
     *
     * A closure rather than a snapshot value, so the caller cannot forget which setting it was and
     * cannot restore it to something it invented.
     *
     * @return Closure(): void
     */
    #[RawSql(
        reason: 'reads the backend the session is actually bound to, which is the whole evidence a pooler leaves behind',
        interpolation: 'the setting name is a constant of this class, and SET takes no parameter for one',
    )]
    private function bound(): Closure
    {
        if (! $this->budget instanceof SessionBudget) {
            return static function (): void {};
        }

        $previous = $this->currentTimeout();
        $this->connection->statement(sprintf("SET statement_timeout = '%dms'", $this->budget->statementTimeoutMs));

        return function () use ($previous): void {
            try {
                $this->connection->statement(sprintf("SET statement_timeout = '%s'", addslashes($previous)));
            } catch (Throwable) {
                // The run is over and its result stands; the connection dying is itself the restore.
            }
        };
    }

    /** The statement timeout in force before the probe, as PostgreSQL reports it. */
    #[RawSql(reason: 'reads a timeout through current_setting(); a builder cannot ask for a GUC')]
    private function currentTimeout(): string
    {
        try {
            $row = $this->connection->selectOne('SHOW statement_timeout');
            $value = is_object($row) ? array_values(get_object_vars($row))[0] ?? null : null;

            return is_scalar($value) ? (string) $value : '0';
        } catch (Throwable) {
            return '0';
        }
    }

    #[RawSql(reason: 'asks pg_backend_pid() -- the value the pooler probe compares across statements')]
    private function backendPid(): int
    {
        /** @var object{pid?: int|string|null}|null $row */
        $row = $this->connection->selectOne('select pg_backend_pid() as pid');

        return is_object($row) ? (int) ($row->pid ?? 0) : 0;
    }

    #[RawSql(reason: 'reads back the setting the probe wrote; the name is this class own constant, so the statement is entirely the package own text')]
    private function probeSetting(): ?string
    {
        // The second argument makes an unset GUC answer NULL rather than raising, so a setting that
        // vanished is an ordinary answer here rather than an exception caught somewhere else.
        /** @var object{value?: string|null}|null $row */
        $row = $this->connection->selectOne(sprintf("select current_setting('%s', true) as value", self::PROBE_SETTING));

        return is_object($row) && is_string($row->value ?? null) ? $row->value : null;
    }
}
