<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Illuminate\Container\Container;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Migrations\Migration;
use LogicException;
use Pushery\SQLens\Contracts\Captor;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Subjects\CaptureMode;
use Throwable;

/**
 * The default capture mode: run a pending migration under Laravel's pretend mode
 * and keep the SQL it would have emitted, without executing any of it.
 *
 * How it works, and why each part is exactly this and not otherwise — every
 * claim here is pinned by a characterization test against the installed
 * framework, because a wrong assumption about pretend does not throw, it
 * produces a run that inspected less than it believes it did (a silent green):
 *
 * - **Connection::pretend()** runs the closure with the connection in pretend
 *   mode and returns the query log — statements are logged, never sent. A table
 *   "created" inside it does not exist afterwards. The captor wraps ONLY the
 *   migration method in that closure: anything else it did there (resolving,
 *   bootstrapping) would land in the log as the migration's own SQL.
 * - **useDefaultSchemaGrammar()** is called first. A connection resolves its
 *   schema grammar lazily, and the lazy path goes through the driver, which
 *   CONNECTS — a 30-second timeout against an unreachable host instead of an
 *   offline run. Building the grammar from the connection object up front makes
 *   the same capture work whether or not a server answers, with no second code
 *   path.
 * - **Each statement is taken the way PDO would receive it**, the SQL with its
 *   placeholders and the bindings beside it, from {@see PretendStatementTap}
 *   rather than from the pretend log. The log's text has the bindings written in
 *   already, by a scanner that reads `\'` as an escape on every driver, so on
 *   PostgreSQL a placeholder behind `'C:\'` stays empty there. The substitution
 *   stage fills the placeholders the way it does for a shadow capture, and the
 *   two modes give the same text. The log is still read, to hold it to the same
 *   statements: when the two disagree, the migration is undetermined and says so.
 *
 * The captor resolves NOTHING about which migrations are pending — it is handed
 * an already-ordered list and works exactly that list, so a run can never quietly
 * cover fewer migrations than the caller believes. A migration the pre-scan has
 * already flagged never reaches here; that gate is wired separately (a detector
 * that also suppressed execution would merge "found" and "prevented").
 *
 * Primum non nocere: no transaction of its own, no write, no `migrate` against a
 * real database. The one thing it runs is the migration method, and only inside
 * the pretend closure that guarantees nothing executes.
 */
final readonly class PretendCaptor implements Captor
{
    private MigrationLoader $loader;

    private DatabaseManager $database;

    private CaptureConnectionFence $fence;

    private PretendStatementTap $tap;

    /**
     * The loader is injectable and SHARED on purpose: the same run reads a migration's forward leg
     * and its rollback leg, and a second `require` of a named-class migration is an uncatchable
     * fatal. See {@see MigrationLoader}.
     *
     * The manager is the one the `Schema` and `DB` facades resolve through, and the fence keeps the
     * method on the capture connection. See {@see self::captureOne()} for both. The tap is shared
     * for the same reason the fence is: it hooks each connection once.
     */
    public function __construct(private Connection $connection, ?MigrationLoader $loader = null, ?DatabaseManager $database = null, ?CaptureConnectionFence $fence = null, ?PretendStatementTap $tap = null)
    {
        $this->loader = $loader ?? new MigrationLoader;
        $this->database = $database ?? Container::getInstance()->make(DatabaseManager::class);
        $this->fence = $fence ?? Container::getInstance()->make(CaptureConnectionFence::class);
        $this->tap = $tap ?? Container::getInstance()->make(PretendStatementTap::class);
    }

    public function capture(iterable $migrations, CaptureSection $section): CaptureRun
    {
        // The grammar is built ONCE, from the connection object, before the first
        // capture — so neither the first migration nor an offline run pays the
        // lazy driver round-trip. Idempotent: calling it again just rebuilds the
        // same grammar.
        $this->connection->useDefaultSchemaGrammar();

        $results = [];

        foreach ($migrations as $migration) {
            $results[] = $this->captureOne($migration, $section);
        }

        return CaptureRun::of($results, $this->mode());
    }

    public function mode(): CaptureMode
    {
        return CaptureMode::Pretend;
    }

    private function captureOne(PendingMigration $pending, CaptureSection $section): CaptureResult
    {
        $method = $section->direction()->value;
        $migration = null;

        try {
            // The facades find the default connection by NAME. A connection built outside the
            // manager has none and cannot become the default, so nothing of the migration runs.
            $name = $this->connection->getNameWithReadWriteType() ?? throw new LogicException('the capture connection has no name, so the facade calls of a migration cannot be pointed at it');

            // Everything the migration file runs happens inside this frame, and nothing of the
            // captor's own: loading the file, which runs its top-level code and the migration's
            // constructor, and the method for this section. `pretend()` returns the log of what
            // they caused, and wrapping anything else would attribute the captor's queries to the
            // migration.
            //
            // The frame has the capture connection as the default, the way Laravel's migrator runs
            // a migration: `Schema::create()` and `DB::table()` without a connection name resolve
            // the default connection, and only this one is pretending. And pretend covers this one
            // connection object, so the fence refuses what the migration sends to any other.
            //
            // The read handle is swapped for one that quotes without a server, and put back. In
            // pretend mode Laravel writes each binding into the logged statement through the read
            // handle's `quote()`, and resolving that handle connects: a migration writing one string
            // value would dial the database. The replacement quotes as the driver's own handle
            // does, so the log is the same whether or not a server answers.
            $readHandle = $this->connection->getRawReadPdo();
            $this->connection->setReadPdo(new OfflineQuotingPdo($this->connection->getDriverName()));

            $elsewhere = null;

            try {
                [$log, $recorded] = $this->tap->recording($this->connection, function () use ($pending, $method, $name, &$migration, &$elsewhere): array {
                    return $this->connection->pretend(function () use ($pending, $method, $name, &$migration, &$elsewhere): void {
                        $this->fence->around($this->connection, function () use ($pending, $method, $name, &$migration, &$elsewhere): void {
                            $this->database->usingConnection($name, function () use ($pending, $method, &$migration, &$elsewhere): void {
                                $migration = $this->loader->load($pending->file);

                                // A migration that names a connection of its own runs there under
                                // `migrate`, and capturing it here would judge it against a database it
                                // never touches. It is not run, and says why below.
                                $elsewhere = $this->declaredElsewhere($migration);

                                if ($elsewhere === null && method_exists($migration, $method)) {
                                    $migration->{$method}();
                                }
                            });
                        });
                    });
                });
            } finally {
                $this->connection->setReadPdo($readHandle);
            }
        } catch (ForeignConnectionRefused $refused) {
            // Not a fault in the migration: it sends a query to a connection this capture does not
            // own, and the fence refused it before it ran. That is the case a declared `$connection`
            // already names, so it is reported the same way, with the connection, rather than as a
            // migration that failed.
            return CaptureResult::undetermined(
                $pending->file,
                $pending->migrationClass,
                $section,
                $this->mode(),
                UndeterminedReason::MigrationOnAnotherConnection,
                annotationClass: $migration instanceof Migration ? $migration::class : null,
                detail: $refused->getMessage(),
            );
        } catch (Throwable $exception) {
            // Laravel writes every binding into the pretend log itself, and refuses a value it has
            // no escape for: a string holding a NUL or invalid UTF-8, an array. The refusal stops
            // the migration's method where it stands, but the migration did nothing wrong, and in
            // shadow mode the same statement runs and is read. So it is not reported as a failure.
            if ($this->thrownWritingThePretendLog($exception)) {
                return CaptureResult::undetermined(
                    $pending->file,
                    $pending->migrationClass,
                    $section,
                    $this->mode(),
                    UndeterminedReason::BindingNotRendered,
                    annotationClass: $migration instanceof Migration ? $migration::class : null,
                    detail: 'the pretend log refused a bound value: '.$exception->getMessage(),
                );
            }

            // A migration that throws under pretend does not crash the run: it is
            // recorded as a failure carrying the exception message, the level-0
            // capture rule judges it, and the remaining migrations still run. The
            // pretend state is already torn down — `pretend()` restores it in its
            // own finally before the throwable reaches here. That holds for a file that
            // cannot be loaded as well, which is why the load sits inside.
            return CaptureResult::failed(
                $pending->file,
                $pending->migrationClass,
                [],
                $section,
                $this->mode(),
                $exception->getMessage(),
                $migration instanceof Migration ? $migration::class : null,
            );
        }

        // The REAL class of the instance loaded above — the carrier of a class-level
        // `#[SqlensIgnore]`. The migration NAME (the file basename) is not a class for
        // Laravel's anonymous migrations, so the annotation layer needs this instead.
        $annotationClass = $migration instanceof Migration ? $migration::class : null;

        if ($elsewhere !== null) {
            return CaptureResult::undetermined(
                $pending->file,
                $pending->migrationClass,
                $section,
                $this->mode(),
                UndeterminedReason::MigrationOnAnotherConnection,
                annotationClass: $annotationClass,
            );
        }

        // A migration without the method for this section (a down-less migration
        // for a `down` run) is a clean, empty result — NOT a failure and NOT an
        // undetermined. The framework's own migrator guards with method_exists for
        // exactly this; capturing nothing here is the honest answer.
        if (! $migration instanceof Migration || ! method_exists($migration, $method)) {
            return CaptureResult::captured($pending->file, $pending->migrationClass, [], $section, $this->mode(), $annotationClass);
        }

        // Both lists come out of the same `Connection::run()` call, one entry per statement. A
        // migration that writes into the query log itself, through `logQuery()`, breaks that, and
        // then which text belongs to which statement is not known. That is reported, not guessed.
        if (count($log) !== count($recorded)) {
            return CaptureResult::undetermined(
                $pending->file,
                $pending->migrationClass,
                $section,
                $this->mode(),
                UndeterminedReason::PretendLogDiverged,
                annotationClass: $annotationClass,
                detail: sprintf('the pretend log holds %d statement(s), and the migration sent %d', count($log), count($recorded)),
            );
        }

        return CaptureResult::captured(
            $pending->file,
            $pending->migrationClass,
            $this->statementsFrom($recorded, $section, $this->withinTransaction($migration)),
            $section,
            $this->mode(),
            $annotationClass,
        );
    }

    /**
     * Whether the exception came from Laravel writing a binding into the pretend log
     * (`Grammar::substituteBindingsIntoRawSql()`), rather than from the migration.
     */
    private function thrownWritingThePretendLog(Throwable $exception): bool
    {
        return array_any($exception->getTrace(), fn (array $frame): bool => $frame['function'] === 'substituteBindingsIntoRawSql');
    }

    /**
     * The connection a migration declares, when it is not the one this run captures on.
     *
     * Laravel's migrator resolves a migration's connection from `getConnection()` and runs the
     * method with it as the default; `null` means the connection being migrated, which is this one.
     * A name that differs, even one that reaches the same database, is another connection as far as
     * the migrator is concerned, and so here.
     *
     * The argument is what {@see MigrationLoader::load()} answered, and the loader answers a migration
     * or throws, so there is no other kind of object to ask.
     */
    private function declaredElsewhere(Migration $migration): ?string
    {
        $declared = $migration->getConnection();

        return is_string($declared) && $declared !== '' && $declared !== $this->connection->getName() ? $declared : null;
    }

    /**
     * Turn the statements the migration sent into ordered captured statements.
     *
     * The SQL and the bindings are kept apart, as a shadow capture keeps them, because writing
     * the one into the other is the substitution stage's job for both modes: this captor grows no
     * inliner of its own.
     *
     * @param  list<array{sql: string, bindings: list<mixed>}>  $recorded
     * @return list<CapturedStatement>
     */
    private function statementsFrom(array $recorded, CaptureSection $section, bool $withinTransaction): array
    {
        $statements = [];
        // A fresh, zero-based sequence: the statement's own ordinal in the migration.
        $sequence = 0;
        // getName() is nullable on the framework's Connection, but a resolved
        // capture connection always has one; the coalesce keeps the value object's
        // non-null contract without a cast that would hide a genuine null.
        $connectionName = $this->connection->getName() ?? '';
        $driver = $this->connection->getDriverName();

        foreach ($recorded as $entry) {
            $statements[] = new CapturedStatement(
                rawSql: $entry['sql'],
                bindings: $entry['bindings'],
                sequence: $sequence,
                direction: $section->direction(),
                withinTransaction: $withinTransaction,
                connectionName: $connectionName,
                driver: $driver,
            );
            $sequence++;
        }

        return $statements;
    }

    /**
     * Whether the migration runs inside a transaction, read off the migration's
     * own `withinTransaction` switch. Recorded on every statement because the
     * canonicalization layer needs it: a statement's transaction context changes
     * what a downtime rule can conclude about it.
     */
    private function withinTransaction(Migration $migration): bool
    {
        // `Migration::$withinTransaction` defaults to true and a migration may set
        // it false; it is a public property, read directly.
        return $migration->withinTransaction;
    }
}
