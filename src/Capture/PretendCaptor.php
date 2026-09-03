<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Illuminate\Database\Connection;
use Illuminate\Database\Migrations\Migration;
use Pushery\SQLens\Contracts\Captor;
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
 * - **The logged `query` already has its bindings inlined** (`values (1)`, not
 *   `values (?)`), with `bindings` still carried separately. The captor keeps
 *   the raw grammar output AND the bindings; turning them into one canonical
 *   string is the substitution and canonicalization stages' job, not this one's.
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

    /**
     * The loader is injectable and SHARED on purpose: the same run reads a migration's forward leg
     * and its rollback leg, and a second `require` of a named-class migration is an uncatchable
     * fatal. See {@see MigrationLoader}.
     */
    public function __construct(private Connection $connection, ?MigrationLoader $loader = null)
    {
        $this->loader = $loader ?? new MigrationLoader;
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
        $migration = $this->loader->load($pending->file);
        $method = $section->direction()->value;

        // A migration without the method for this section (a down-less migration
        // for a `down` run) is a clean, empty result — NOT a failure and NOT an
        // undetermined. The framework's own migrator guards with method_exists for
        // exactly this; capturing nothing here is the honest answer.
        // The REAL class of the instance just loaded — the carrier of a class-level
        // `#[SqlensIgnore]`. The migration NAME (the file basename) is not a class for
        // Laravel's anonymous migrations, so the annotation layer needs this instead.
        $annotationClass = $migration::class;

        if (! method_exists($migration, $method)) {
            return CaptureResult::captured($pending->file, $pending->migrationClass, [], $section, $this->mode(), $annotationClass);
        }

        $withinTransaction = $this->withinTransaction($migration);

        try {
            // ONLY the migration method is inside the closure. `pretend()` returns
            // the log of everything the method caused; wrapping anything else would
            // attribute the captor's own queries to the migration.
            $log = $this->connection->pretend(static function () use ($migration, $method): void {
                $migration->{$method}();
            });
        } catch (Throwable $exception) {
            // A migration that throws under pretend does not crash the run: it is
            // recorded as a failure carrying the exception message, the level-0
            // capture rule judges it, and the remaining migrations still run. The
            // pretend state is already torn down — `pretend()` restores it in its
            // own finally before the throwable reaches here.
            return CaptureResult::failed(
                $pending->file,
                $pending->migrationClass,
                [],
                $section,
                $this->mode(),
                $exception->getMessage(),
                $annotationClass,
            );
        }

        return CaptureResult::captured(
            $pending->file,
            $pending->migrationClass,
            $this->statementsFrom($log, $section, $withinTransaction),
            $section,
            $this->mode(),
            $annotationClass,
        );
    }

    /**
     * Turn the pretend query log into ordered captured statements.
     *
     * The raw grammar output and the bindings are kept as the framework hands
     * them over — separate — because the substitution stage owns turning them
     * into one string and this captor must not grow a second, divergent inliner.
     *
     * @param  array<array-key, array{query: string, bindings: array<array-key, mixed>, time: float|null}>  $log  the shape Connection::pretend() declares
     * @return list<CapturedStatement>
     */
    private function statementsFrom(array $log, CaptureSection $section, bool $withinTransaction): array
    {
        $statements = [];
        // A fresh, zero-based sequence, independent of whatever keys the log
        // happened to carry — the statement's own ordinal, not the log's.
        $sequence = 0;
        // getName() is nullable on the framework's Connection, but a resolved
        // capture connection always has one; the coalesce keeps the value object's
        // non-null contract without a cast that would hide a genuine null.
        $connectionName = $this->connection->getName() ?? '';
        $driver = $this->connection->getDriverName();

        foreach ($log as $entry) {
            $statements[] = new CapturedStatement(
                rawSql: $entry['query'],
                bindings: array_values($entry['bindings']),
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
