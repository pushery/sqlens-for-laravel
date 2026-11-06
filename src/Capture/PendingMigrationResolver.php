<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Migrations\Migrator;
use Illuminate\Database\QueryException;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Contracts\PendingResolver;
use Pushery\SQLens\Security\PathBinding;
use Throwable;

/**
 * Resolves which migrations are pending, in which order, for a connection — the
 * input to every lint run — by composing the answer from the Laravel migrator's
 * file discovery and the migration-repository table, without ever writing to it.
 *
 * The migrator has no public "which are pending" method, so this composes it the
 * way the migrator does internally: the migration files (discovered and sorted by
 * name, never by filesystem order) minus the migrations already recorded as run.
 * The order is therefore deterministic across machines, and the prospective batch
 * number is the next one the migrator would assign.
 *
 * Two promises are held here structurally:
 *
 *   - **It only reads.** Every query is a `SELECT` — the migration table's rows and
 *     its highest batch — and it takes no lock. It never records or removes a
 *     migration; that is the migrator's job under a real `migrate`, never a lint's.
 *   - **It reads the WRITE side.** On a read/write split the read replica can lag,
 *     so a migration just recorded might not show there yet and would be
 *     mis-reported as still pending. The repository reads therefore use the write
 *     PDO explicitly, so "pending" reflects the instance deployments target.
 *
 * And the dangerous shape is refused: an unreachable connection, a missing
 * migration table, or an empty migration path is a named skip, never an empty list
 * read as "nothing pending, all clean".
 *
 * `Migrator::withoutMigrations()` (a harness feature that excludes specific
 * migrations from a run) is not honored here — it is set at migrate time by a test
 * harness, not something a lint sees, and its state is not publicly readable. A
 * migration a harness excluded would be reported as pending, which for a read-only
 * lint over-reports rather than misses.
 *
 * @param  list<string>  $migrationPaths
 */
final readonly class PendingMigrationResolver implements PendingResolver
{
    /**
     * @param  list<string>  $migrationPaths
     * @param  SessionGuard  $sessionGuard  bounds the borrowed session around the catalog reads
     *                                      below. REQUIRED rather than defaulted: a default would
     *                                      be a second answer to "how long may this run wait",
     *                                      free to diverge from the configured one without saying
     *                                      so, and the unbounded read is what this parameter
     *                                      exists to make impossible.
     * @param  bool  $includeVendorMigrations  whether a migration discovered inside `vendor/` is
     *                                         enumerated. False drops it before anything reads it;
     *                                         see {@see self::vendorFiltered()} for what is never
     *                                         dropped and why.
     */
    public function __construct(
        private DatabaseManager $db,
        private Migrator $migrator,
        private array $migrationPaths,
        private string $migrationsTable,
        private string $projectRoot,
        private SessionGuard $sessionGuard,
        private bool $includeVendorMigrations = true,
    ) {}

    public function resolve(string $connection): PendingResolution
    {
        if ($this->migrationPaths === []) {
            return PendingResolution::skipped(PendingSkipReason::EmptyMigrationPath);
        }

        $target = $this->db->connection($connection);

        // Reachability first: a connection that cannot be opened is a named skip, not
        // an empty pending list read as success.
        try {
            $target->getPdo();
        } catch (Throwable) {
            return PendingResolution::skipped(PendingSkipReason::ConnectionUnreachable);
        }

        // The bound sits here, in the resolver, and not at the call sites. Three commands read
        // the pending state — `sqlens:lint`, `sqlens:drift` and `sqlens:postdeploy --expect-shadow`
        // — each of them possibly against a production connection, and `sqlens:drift` is the
        // likeliest to point at production: comparing what is against what should be is its whole
        // purpose. A bound left to each call site is one a caller can forget; a caller cannot
        // forget what it cannot construct without.
        //
        // After the reachability check and before the first catalog read, which is the only correct
        // window rather than a stylistic choice. The bound writes with `Connection::statement()`,
        // which throws on an unreachable server — binding above would turn the named
        // `ConnectionUnreachable` skip into a stack trace, replacing the specific answer with a
        // crash. Inside it are the three reads this bounds.
        //
        // Nesting is safe by construction, which is what lets the lint path keep its own outer
        // bound. On MySQL the guard snapshots whatever it finds and restores exactly that, so an
        // inner bound over an identical outer one restores the outer value rather than the pre-run
        // one. On PostgreSQL the inner window is a savepoint, and rolling back to it puts the outer
        // `SET LOCAL` back.
        $resolution = $this->sessionGuard->within(
            $target,
            fn (): PendingResolution => $this->resolveBounded($target, $connection),
        );

        // The grant is named after the window has closed, not inside it. On PostgreSQL the refused
        // read aborts the window's transaction, so every statement after it in there is refused as
        // well; the rollback that ends the window makes the session usable again.
        return $resolution->skip === PendingSkipReason::MigrationTableUnreadable
            ? PendingResolution::skipped(PendingSkipReason::MigrationTableUnreadable, $this->grantFor($target))
            : $resolution;
    }

    /**
     * The reads themselves, with the session already bounded by {@see self::resolve()}.
     *
     * Split out so the whole set runs inside the guard's window: every exit below — three named
     * skips and the resolved list — happens inside it, and a path somebody adds later does too.
     */
    private function resolveBounded(Connection $target, string $connection): PendingResolution
    {
        // The migration repository must exist, or "which ran" is unknowable — a fresh
        // project is distinguished from a broken connection this way.
        //
        // Asked inside a transaction, which is how a schema question reaches the WRITE side: the
        // schema builder has no useWritePdo(), and a connection in a transaction reads on the
        // session it writes on. On a read/write split the question otherwise goes to a replica,
        // whose session the guard never bounded, and a lagging one answers NoMigrationTable.
        if (! $target->transaction(fn (): bool => $target->getSchemaBuilder()->hasTable($this->migrationsTable))) {
            return PendingResolution::skipped(PendingSkipReason::NoMigrationTable);
        }

        // Files, discovered and sorted by migration name (never filesystem order).
        $files = $this->migrator->getMigrationFiles($this->migrationPaths);

        if ($files === []) {
            return PendingResolution::skipped(PendingSkipReason::EmptyMigrationPath);
        }

        // The already-run migrations and the last batch, read from the WRITE side so a
        // lagging replica cannot make a recorded migration look pending.
        //
        // A role that may not read the table is refused here, after the table check above has
        // answered yes: PostgreSQL's catalog lists a table to every role, MySQL's to an account
        // holding any privilege on it, and only SELECT reads its rows. That refusal is a named skip
        // like the others, not an exception that ends the run without a report; any other failure
        // of the read stays the failure it is.
        try {
            $read = $target->table($this->migrationsTable)->useWritePdo()->pluck('migration')->all();
            $maxBatch = $target->table($this->migrationsTable)->useWritePdo()->max('batch');
        } catch (QueryException $exception) {
            if (! $this->refusedByPrivilege($exception)) {
                throw $exception;
            }

            return PendingResolution::skipped(PendingSkipReason::MigrationTableUnreadable);
        }

        // The reads alone stand in the `try`, so the filter over what they returned is a branch
        // line coverage can see.
        $ran = [];

        foreach ($read as $migration) {
            if (is_string($migration)) {
                $ran[] = $migration;
            }
        }

        $batch = (is_numeric($maxBatch) ? (int) $maxBatch : 0) + 1;

        $outstanding = array_diff_key($files, array_flip($ran));
        $pending = $this->vendorFiltered($outstanding);

        // Something was waiting to run, and every one of those migrations was a package's. That is
        // a different fact from "nothing is pending", and it gets its own skip rather than an empty
        // list: the run really did find migrations to judge and really is not judging them, and a
        // reader told that nothing was read would stop looking while a package's migration waits.
        //
        // The question is asked of the pending set, not of the files on disk. An application's own
        // migrations have normally all run, so "was every discovered file a package's" is answered
        // no by files that will never run again, and the skip was only reached by an application
        // with no migrations of its own.
        if ($outstanding !== [] && $pending === []) {
            return PendingResolution::skipped(PendingSkipReason::OnlyVendorMigrations);
        }

        $migrations = [];
        $index = 0;

        foreach ($pending as $name => $path) {
            $migrations[] = new PendingMigration(
                file: $path,
                migrationClass: (string) $name,
                relativePath: $this->relativePath($path),
                orderIndex: $index,
                batchNumber: $batch,
                connection: $connection,
            );
            $index++;
        }

        return PendingResolution::resolved($migrations);
    }

    /**
     * Whether the server refused the read because the role may not read the table.
     *
     * PostgreSQL names the refusal with its own SQLSTATE, `42501`. MySQL answers `42000`, the class it
     * shares with a syntax error, so there the driver's code decides: `1142` is a table the account
     * holds no privilege on.
     */
    private function refusedByPrivilege(QueryException $exception): bool
    {
        $state = $exception->errorInfo[0] ?? null;
        $code = $exception->errorInfo[1] ?? null;

        return $state === '42501' || ($state === '42000' && is_numeric($code) && (int) $code === 1142);
    }

    /**
     * What lets the reading role read the migration repository table, as a sentence with the statement.
     *
     * The role is asked of the server rather than read from the configuration: a `url` connection and
     * a read/write split each name the account somewhere else than the configuration's `username`,
     * and the refused read went to the write side, which is where this asks too. Where the server
     * will not say, the sentence names the table alone.
     */
    #[RawSql(reason: 'asks the session which role it reads as; current_user has no query builder expression')]
    private function grantFor(Connection $target): string
    {
        $table = $target->getTablePrefix().$this->migrationsTable;
        $driver = $target->getDriverName();

        // The question is chosen before the `try`, so the read is all that stands in it.
        $question = match ($driver) {
            'pgsql' => 'select current_user as reader',
            'mysql' => 'select current_user() as reader',
            default => null,
        };
        $row = null;

        if ($question !== null) {
            try {
                $row = $target->selectOne($question, [], false);
            } catch (Throwable) {
                $row = null;
            }
        }

        $reader = is_object($row) ? ($row->reader ?? null) : null;

        // PostgreSQL lets the table's owner grant on it, which is the role the migrations run as.
        // MySQL has no owner of a table: an account holding the privilege with GRANT OPTION grants it.
        $grantor = $driver === 'mysql' ? 'As an account that may grant it' : 'As the table\'s owner';

        if (! is_string($reader) || $reader === '') {
            return sprintf('%s, grant SELECT on `%s` to the role this connection reads as.', $grantor, $table);
        }

        $statement = $driver === 'mysql'
            ? sprintf('GRANT SELECT ON %s.%s TO %s;', $this->mysqlIdentifier($target->getDatabaseName()), $this->mysqlIdentifier($table), $this->mysqlAccount($reader))
            : sprintf('GRANT SELECT ON %s TO %s;', implode('.', array_map($this->pgIdentifier(...), explode('.', $table))), $this->pgIdentifier($reader));

        return sprintf('%s, run `%s`', $grantor, $statement);
    }

    /** A PostgreSQL identifier as it has to be written: bare when it folds to itself, quoted otherwise. */
    private function pgIdentifier(string $name): string
    {
        return preg_match('/^[a-z_][a-z0-9_$]*$/', $name) === 1 ? $name : '"'.str_replace('"', '""', $name).'"';
    }

    /** A MySQL identifier, bare when it holds only the characters MySQL reads unquoted. */
    private function mysqlIdentifier(string $name): string
    {
        return preg_match('/^[A-Za-z0-9_$]+$/', $name) === 1 ? $name : '`'.str_replace('`', '``', $name).'`';
    }

    /** `CURRENT_USER()` answers `user@host`; a grant names the account as `'user'@'host'`. */
    private function mysqlAccount(string $reader): string
    {
        $at = strrpos($reader, '@');

        return $at === false
            ? "'".str_replace("'", "''", $reader)."'"
            : "'".str_replace("'", "''", substr($reader, 0, $at))."'@'".str_replace("'", "''", substr($reader, $at + 1))."'";
    }

    /**
     * The discovered files, less the ones that live inside the dependency tree.
     *
     * ## Why the enumeration filters at all, when the classifier already knew
     *
     * The capture layer has always known a `vendor/` migration from one of yours — that is what
     * {@see PathBinding} decides, and what
     * `security.include_vendor_migrations` switches. But it decides it about a statement that has
     * already been captured, so a package's migration was still loaded, still pretend-executed, and
     * still able to produce a capture-layer finding of its own. A first run after `composer require`
     * therefore failed on three findings inside another package, none of which the project could
     * fix, every one of them repeating on every run.
     *
     * The switch's own docblock makes the argument, and it holds here just as well: a rule whose
     * only available fix is "open an issue upstream" is one people silence wholesale, taking the
     * findings they COULD have acted on with it. It weighs more for `lint`, the suite that hangs in
     * CI, where the gate would be red on day one over another package's migrations.
     *
     * ## What is deliberately not filtered
     *
     * A path somebody named. `--path`, `sqlens.migration_paths` and `--file` are a person saying
     * "these", and quietly dropping part of what they named would make the argument advisory. The
     * caller decides that and it arrives here as `$includeVendorMigrations`.
     *
     * `sqlens:predeploy` passes true as well, and that one is not a preference: a package's
     * migration RUNS during a deploy and can take an ACCESS EXCLUSIVE lock like any other. Hiding it
     * from the run that exists to see what the deploy is about to walk into would answer that
     * question wrongly.
     *
     * @param  array<string, string>  $files
     * @return array<string, string>
     */
    private function vendorFiltered(array $files): array
    {
        if ($this->includeVendorMigrations) {
            return $files;
        }

        // Through `VendorPath`, which RESOLVES before it matches. Matching the raw path here would
        // disagree with the capture layer under a Composer `path` repository — the raw path still
        // carries `/vendor/` where the resolved one does not — and the file would then be dropped
        // from the enumeration while the classifier bound it as a migration of yours.
        return array_filter($files, fn (string $path): bool => ! VendorPath::contains($path, $this->projectRoot));
    }

    /** The repo-relative path — deterministic across machines, and what a finding shows. */
    private function relativePath(string $path): string
    {
        return str_replace(rtrim($this->projectRoot, '/').'/', '', $path);
    }
}
