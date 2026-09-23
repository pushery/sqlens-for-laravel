<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Catalog;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\PoolerReading;
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

    /**
     * No session budget. See {@see self::read()} for why a session `SET statement_timeout` would
     * be the very leak the probe exists to detect, and what is carried instead.
     */
    public function __construct(private Connection $connection) {}

    #[RawSql(reason: 'detects a connection pooler by setting a session setting and reading it back on what should be the same backend; SET has no builder verb')]
    public function read(): PoolerReading
    {
        $convention = $this->conventionSignals();

        try {
            // Not bounded by a session `SET statement_timeout`, and deliberately.
            //
            // The probe is the one read in the package that cannot run inside a transaction —
            // pooling is invisible in one, which is the guarantee a pooler exists to give — so
            // `SET LOCAL`, which every other reader uses, is not available here. That leaves a plain
            // session `SET`, and on the connection this probe is most needed on it is precisely the
            // leak being measured: the `SET` lands on one backend, the restore looks for it on
            // another, and the host application inherits a timeout it never chose, set by the code
            // whose job is to detect that this can happen.
            //
            // What is given up is named rather than waved away: four constant-time statements run
            // with whatever bound the connection already carries, usually none. That is a risk to
            // this run — a pooler that accepts a connection and never answers holds it — and the
            // leak would be a risk to somebody else's session. Between a hazard we carry and one we hand
            // to a stranger, the package takes its own.

            // Two separate statements, outside any transaction. Inside one, a transaction pooler
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
     * `pg_catalog.`-qualified, like every call this probe makes. An unqualified catalog
     * function can be outranked by a user function whose signature matches more closely, and this
     * probe runs outside a transaction, where nothing else covers it.
     *
     * Measured on PostgreSQL 18.0 rather than assumed: a user `public.pg_backend_pid()` does not
     * outrank the catalog one, and neither does a `public.current_setting(text)` — for an identical
     * signature `pg_catalog` is searched first and wins. So neither call here was exploitable. The
     * qualification is still worth its four characters: it makes that a property of the line rather
     * than of an argument type, and the day one of these takes a parameter whose type stops being
     * an exact match, nothing silently changes answer.
     */
    #[RawSql(reason: 'asks pg_backend_pid() -- the value the pooler probe compares across statements')]
    private function backendPid(): int
    {
        /** @var object{pid?: int|string|null}|null $row */
        $row = $this->connection->selectOne('select pg_catalog.pg_backend_pid() as pid');

        return is_object($row) ? (int) ($row->pid ?? 0) : 0;
    }

    #[RawSql(reason: 'reads back the setting the probe wrote; the name is this class own constant, so the statement is entirely the package own text')]
    private function probeSetting(): ?string
    {
        // The second argument makes an unset GUC answer NULL rather than raising, so a setting that
        // vanished is an ordinary answer here rather than an exception caught somewhere else.
        /** @var object{value?: string|null}|null $row */
        $row = $this->connection->selectOne(sprintf("select pg_catalog.current_setting('%s', true) as value", self::PROBE_SETTING));

        return is_object($row) && is_string($row->value ?? null) ? $row->value : null;
    }
}
