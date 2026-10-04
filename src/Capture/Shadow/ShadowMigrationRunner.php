<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

use Closure;
use Illuminate\Container\Container;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Grammars\Grammar;
use Pushery\SQLens\Capture\CaptureConnectionFence;
use Pushery\SQLens\Capture\CaptureResult;
use Pushery\SQLens\Capture\CaptureRun;
use Pushery\SQLens\Capture\CaptureSection;
use Pushery\SQLens\Capture\DriverMessage;
use Pushery\SQLens\Capture\ForeignConnectionRefused;
use Pushery\SQLens\Capture\MigrationLoader;
use Pushery\SQLens\Capture\PendingMigration;
use Pushery\SQLens\Contracts\ShadowRunner;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Subjects\CaptureMode;
use ReflectionProperty;
use Throwable;

/**
 * Runs the real migrations against a provisioned shadow database and captures the
 * SQL they emit — the truth-mode counterpart to intercepting a pretend log, and the
 * one place a migration actually executes.
 *
 * It shares everything downstream with the pretend path: the same `CaptureResult`
 * shape, the same `CapturedStatement` (raw SQL and bindings kept separate), and the
 * same substitution and canonicalization layer applied afterwards — there is one
 * data path into the rules, never a second "fast" and "correct" engine. The only
 * difference is HOW the SQL is obtained: a query listener on the shadow connection
 * while each migration's method runs for real, instead of Laravel's pretend log.
 *
 * Attribution is exact by construction, not by counting: each migration's method is
 * run inside its own window, the collector is reset before it and taken after, so a
 * statement belongs to exactly the migration whose window produced it. The runner's own
 * statements never enter one: the session limits are set before the listener exists, and
 * the migration method is called directly rather than through the Migrator, so no row is
 * written to the migrations table while a window is open. Everything the window records
 * is the migration's, and it reaches the rules whole, exactly as the pretend log does.
 *
 * The default connection is pointed at the shadow for the duration of the run so a
 * migration's `Schema`/`DB` calls land on it, and restored afterwards. So is the NAME of the
 * linted connection: a migration that names it, as Telescope's does through `getConnection()`,
 * means the database this run stands in for, and reaches the shadow too. The listener
 * is registered per run on the (throwaway) shadow connection; because each run reads
 * only its OWN collector, a listener left on a reused connection cannot corrupt a
 * later run's capture.
 */
final readonly class ShadowMigrationRunner implements ShadowRunner
{
    private CaptureConnectionFence $fence;

    private MigrationLoader $loader;

    public function __construct(
        private DatabaseManager $db,
        private ?ShadowSessionDefense $defense = null,
        ?CaptureConnectionFence $fence = null,
    ) {
        $this->fence = $fence ?? Container::getInstance()->make(CaptureConnectionFence::class);
        $this->loader = new MigrationLoader;
    }

    public function captureFrom(ShadowSession $session, iterable $migrations, CaptureSection $section): CaptureRun
    {
        $connection = $this->db->connection($session->connectionName);

        // Bound this session's own budgets BEFORE the listener is attached, so the
        // defensive SET statements never appear as captured SQL — a shadow run must
        // not itself sit on the source instance holding a statement or a lock.
        $this->defense?->apply($connection);

        $collector = new ShadowStatementCollector(
            $connection->getName() ?? '',
            $connection->getDriverName(),
        );

        $connection->listen(static function (QueryExecuted $query) use ($collector): void {
            $collector->record($query->sql, $query->bindings);
        });

        // A migration's Schema/DB calls target the default connection; point it at
        // the shadow for the run and restore it afterwards, whatever happens.
        $previousDefault = $this->db->getDefaultConnection();
        $this->db->setDefaultConnection($session->connectionName);
        $restoreSource = $this->resolveSourceToShadow($session->sourceConnection, $connection);

        try {
            $results = [];
            $failed = false;

            foreach ($migrations as $pending) {
                // Once a migration has failed the real migrate, the database is in a
                // partial state: running the rest on top of it would fail or lint
                // against a schema that never really formed. So every migration after
                // the failure is undetermined (shadow_migrate_failed) — not a pass, not
                // silently empty — while the one that failed carries its own finding.
                if ($failed) {
                    $results[] = CaptureResult::undetermined(
                        $pending->file,
                        $pending->migrationClass,
                        $section,
                        CaptureMode::Shadow,
                        UndeterminedReason::ShadowMigrateFailed,
                    );

                    continue;
                }

                $result = $this->captureOne($pending, $section, $collector, $connection);
                $results[] = $result;
                // A failure OR a session timeout halts the run: in both cases the
                // database is in a state the rest of the migrations cannot trust.
                $failed = $result->isFail() || $result->isUndetermined();
            }
        } finally {
            $restoreSource();
            $this->db->setDefaultConnection($previousDefault);
        }

        return CaptureRun::of($results, CaptureMode::Shadow);
    }

    /**
     * Resolve the linted connection's NAME to the shadow connection for the run, and hand back what
     * restores it.
     *
     * A migration that names the connection being linted means the database the shadow stands in
     * for, and before this it reached the real one, which the fence refuses: the migration failed as
     * `CAP.L0.MIGRATE_ERROR` and every migration after it went unjudged. The manager has no setter
     * for one cached connection that leaves the others alone, and `purge()` would disconnect a
     * connection the host application may still hold, so the cached object is set aside rather than
     * closed, and put back afterwards. Any other name still reaches its own connection, and the
     * fence still refuses it.
     *
     * @return Closure(): void
     */
    private function resolveSourceToShadow(string $source, Connection $shadow): Closure
    {
        $cache = new ReflectionProperty(DatabaseManager::class, 'connections');
        $connections = (array) $cache->getValue($this->db);
        $held = $connections[$source] ?? null;
        $connections[$source] = $shadow;
        $cache->setValue($this->db, $connections);

        return function () use ($cache, $source, $held): void {
            $connections = (array) $cache->getValue($this->db);
            unset($connections[$source]);
            $cache->setValue($this->db, $held === null ? $connections : [...$connections, $source => $held]);
        };
    }

    /**
     * A migration that sends a query to a connection the capture does not own, refused by the fence
     * before it ran: not a fault in the migration, and the case a declared `$connection` already
     * names, so it is reported the same way, with the connection, as the pretend path reports it.
     */
    private function onAnotherConnection(PendingMigration $pending, CaptureSection $section, ForeignConnectionRefused $refused, ?string $annotationClass = null): CaptureResult
    {
        return CaptureResult::undetermined(
            $pending->file,
            $pending->migrationClass,
            $section,
            CaptureMode::Shadow,
            UndeterminedReason::MigrationOnAnotherConnection,
            annotationClass: $annotationClass,
            detail: $refused->getMessage(),
        );
    }

    /**
     * A migration whose session the server ended, by termination, restart or a dropped network:
     * undetermined with the driver's words, not a `CAP.L0.MIGRATE_ERROR` about a migration that never
     * reached a verdict and may well be sound.
     */
    private function connectionLost(PendingMigration $pending, CaptureSection $section, Throwable $lost, ?string $annotationClass = null): CaptureResult
    {
        return CaptureResult::undetermined(
            $pending->file,
            $pending->migrationClass,
            $section,
            CaptureMode::Shadow,
            UndeterminedReason::ShadowConnectionLost,
            annotationClass: $annotationClass,
            detail: $this->safeDetail($lost),
        );
    }

    private function captureOne(PendingMigration $pending, CaptureSection $section, ShadowStatementCollector $collector, Connection $shadow): CaptureResult
    {
        // Loading runs the file's top-level code and the migration's constructor. The default
        // connection is the shadow already, and what they send to any other the fence refuses; a
        // file that cannot be loaded is a failed migration rather than the end of the run.
        try {
            $migration = $this->fence->around($shadow, fn (): Migration => $this->load($pending->file));
        } catch (ForeignConnectionRefused $refused) {
            return $this->onAnotherConnection($pending, $section, $refused);
        } catch (Throwable $throwable) {
            if (ConnectionLossDetector::isConnectionLoss($throwable)) {
                return $this->connectionLost($pending, $section, $throwable);
            }

            return CaptureResult::failed($pending->file, $pending->migrationClass, [], $section, CaptureMode::Shadow, $this->safeDetail($throwable));
        }

        $method = $section->direction()->value;

        // The REAL class of the loaded instance — the carrier of a class-level
        // `#[SqlensIgnore]`, exactly as the pretend path records it, so a suppression
        // behaves identically in both capture modes.
        $annotationClass = $migration::class;

        if (! method_exists($migration, $method)) {
            // On the roundtrip's DOWN leg this is the difference between two facts
            // that must never be conflated: "there is no rollback path" and "the
            // rollback path does not invert". A clean empty result would say the
            // second — the roundtrip would go on, the second `up` would fail against
            // the schema the first one left, and the run would report a broken
            // inverse for a migration that never declared one. So it is undetermined
            // with its own reason, and the roundtrip stops there.
            if ($section === CaptureSection::Down) {
                return CaptureResult::undetermined(
                    $pending->file,
                    $pending->migrationClass,
                    $section,
                    CaptureMode::Shadow,
                    UndeterminedReason::RoundtripNoDownMethod,
                    annotationClass: $annotationClass,
                );
            }

            // Any other section: nothing to run, a clean empty result, exactly as the
            // pretend path treats it.
            return CaptureResult::captured($pending->file, $pending->migrationClass, [], $section, CaptureMode::Shadow, $annotationClass);
        }

        $withinTransaction = $migration->withinTransaction;
        $collector->reset();

        try {
            // The default connection is the shadow, and a migration that names another connection
            // would reach a real database: the fence refuses its queries before they run.
            $this->fence->around($shadow, fn () => $this->asTheMigratorRunsIt($shadow, $migration, $method));
        } catch (ForeignConnectionRefused $refused) {
            return $this->onAnotherConnection($pending, $section, $refused, $annotationClass);
        } catch (Throwable $throwable) {
            // A session timeout is the tool's OWN budget firing, not a fault in the
            // migration, so it is undetermined (shadow_session_timeout) — never a
            // CAP.L0.MIGRATE_ERROR and never a passed-through exception.
            if (SessionTimeoutDetector::isSessionTimeout($throwable)) {
                return CaptureResult::undetermined(
                    $pending->file,
                    $pending->migrationClass,
                    $section,
                    CaptureMode::Shadow,
                    UndeterminedReason::ShadowSessionTimeout,
                    annotationClass: $annotationClass,
                );
            }

            // The server ended the session: the statement never reached a verdict. Asked after the
            // timeout, because a budget firing is the tool's own doing and has its own reason.
            if (ConnectionLossDetector::isConnectionLoss($throwable)) {
                return $this->connectionLost($pending, $section, $throwable, $annotationClass);
            }

            // A migration that fails mid-run is a failure carrying the driver's own
            // message (CAP.L0.MIGRATE_ERROR judges it). The statements captured BEFORE
            // the failure are kept — they are evidence — while everything after this
            // migration is undetermined. The shadow database is thrown away by the
            // captor's teardown regardless.
            return CaptureResult::failed(
                $pending->file,
                $pending->migrationClass,
                $collector->take($section, $withinTransaction),
                $section,
                CaptureMode::Shadow,
                $this->safeDetail($throwable),
                $annotationClass,
            );
        }

        return CaptureResult::captured(
            $pending->file,
            $pending->migrationClass,
            $collector->take($section, $withinTransaction),
            $section,
            CaptureMode::Shadow,
            $annotationClass,
        );
    }

    /**
     * Run a migration method the way Laravel's `Migrator` does: inside one transaction where the
     * schema grammar supports transactional DDL and the migration has not opted out of it.
     *
     * The truth mode exists to find what a real `migrate` does, and on PostgreSQL a real `migrate`
     * runs each migration in a transaction. Three things only happen there: a caught error aborts
     * the transaction, so the next statement fails with 25P02; `CREATE INDEX CONCURRENTLY` is
     * refused inside a transaction block; and a value added to an enum cannot be used before the
     * transaction commits. Run in autocommit, all three passed here and failed at deploy.
     *
     * The condition is Laravel's own, read the same way: the grammar is resolved as the `Migrator`
     * resolves it, and `withinTransaction` is the migration's own switch. MySQL's grammar reports no
     * schema transactions, so nothing changes there.
     */
    private function asTheMigratorRunsIt(Connection $shadow, Migration $migration, string $method): void
    {
        $run = static function () use ($migration, $method): void {
            $migration->{$method}();
        };

        if ($migration->withinTransaction && $this->schemaGrammar($shadow)->supportsSchemaTransactions()) {
            $shadow->transaction($run);

            return;
        }

        $run();
    }

    /**
     * The connection's schema grammar.
     *
     * A connection sets it up lazily, and asking for the schema builder is what does so, the same
     * default the `Migrator` falls back to before it asks the grammar anything.
     */
    private function schemaGrammar(Connection $connection): Grammar
    {
        $connection->getSchemaBuilder();

        return $connection->getSchemaGrammar();
    }

    /**
     * The driver message to record for a failed migration. For a query failure the
     * PDOException's OWN message is preferred over Laravel's `QueryException`
     * wrapper: the wrapper appends "(Connection: …, SQL: …)", carrying the connection
     * name and the statement, while the PDOException is the bare SQLSTATE and driver
     * text. Credentials are stripped again by the rule before the message is shown;
     * this keeps the stored detail lean at the source.
     */
    private function safeDetail(Throwable $throwable): string
    {
        return DriverMessage::of($throwable);
    }

    /**
     * The migration instance for a file, through the loader the pretend path uses: it knows both
     * shapes Laravel accepts, a returned anonymous class and a declared named one, names a file that
     * is neither, and never requires a named class twice, which a roundtrip's second leg would.
     *
     * Nothing reaches here until the pre-scan has judged the file safe, so the `require` that runs
     * its top-level code is not a new risk.
     */
    private function load(string $file): Migration
    {
        return $this->loader->load($file);
    }
}
