<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\QueryException;
use Pushery\SQLens\Capture\CaptureResult;
use Pushery\SQLens\Capture\CaptureRun;
use Pushery\SQLens\Capture\CaptureSection;
use Pushery\SQLens\Capture\PendingMigration;
use Pushery\SQLens\Contracts\ShadowRunner;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Subjects\CaptureMode;
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
 * statement belongs to exactly the migration whose window produced it. Repository
 * bookkeeping, session setup, and transaction brackets are dropped by the
 * {@see ShadowNoiseFilter} — the `migrations` table never reaches a rule.
 *
 * The default connection is pointed at the shadow for the duration of the run so a
 * migration's `Schema`/`DB` calls land on it, and restored afterwards. The listener
 * is registered per run on the (throwaway) shadow connection; because each run reads
 * only its OWN collector, a listener left on a reused connection cannot corrupt a
 * later run's capture.
 */
final readonly class ShadowMigrationRunner implements ShadowRunner
{
    public function __construct(
        private DatabaseManager $db,
        private ShadowNoiseFilter $filter,
        private string $migrationsTable,
        private ?ShadowSessionDefense $defense = null,
    ) {}

    public function captureFrom(ShadowSession $session, iterable $migrations, CaptureSection $section): CaptureRun
    {
        $connection = $this->db->connection($session->connectionName);

        // Bound this session's own budgets BEFORE the listener is attached, so the
        // defensive SET statements never appear as captured SQL — a shadow run must
        // not itself sit on the source instance holding a statement or a lock.
        $this->defense?->apply($connection);

        $collector = new ShadowStatementCollector(
            $this->filter,
            $this->migrationsTable,
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

                $result = $this->captureOne($pending, $section, $collector);
                $results[] = $result;
                // A failure OR a session timeout halts the run: in both cases the
                // database is in a state the rest of the migrations cannot trust.
                $failed = $result->isFail() || $result->isUndetermined();
            }
        } finally {
            $this->db->setDefaultConnection($previousDefault);
        }

        return CaptureRun::of($results, CaptureMode::Shadow);
    }

    private function captureOne(PendingMigration $pending, CaptureSection $section, ShadowStatementCollector $collector): CaptureResult
    {
        $migration = $this->load($pending->file);
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
            $migration->{$method}();
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
     * The driver message to record for a failed migration. For a query failure the
     * PDOException's OWN message is preferred over Laravel's `QueryException`
     * wrapper: the wrapper appends "(Connection: …, SQL: …)", carrying the connection
     * name and the statement, while the PDOException is the bare SQLSTATE and driver
     * text. Credentials are stripped again by the rule before the message is shown;
     * this keeps the stored detail lean at the source.
     */
    private function safeDetail(Throwable $throwable): string
    {
        return $throwable instanceof QueryException && $throwable->getPrevious() instanceof Throwable
            ? $throwable->getPrevious()->getMessage()
            : $throwable->getMessage();
    }

    /**
     * Load a migration from its file — a Laravel 13 anonymous class the file
     * RETURNS. Nothing reaches here until the pre-scan has judged the file safe, so
     * the `require` that runs its top-level code is not a new risk.
     */
    private function load(string $file): Migration
    {
        /** @var Migration $migration */
        $migration = require $file;

        return $migration;
    }
}
