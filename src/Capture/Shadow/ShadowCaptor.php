<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

use DateTimeImmutable;
use DateTimeZone;
use Pushery\SQLens\Capture\CaptureResult;
use Pushery\SQLens\Capture\CaptureRun;
use Pushery\SQLens\Capture\CaptureSection;
use Pushery\SQLens\Capture\PendingMigration;
use Pushery\SQLens\Contracts\Captor;
use Pushery\SQLens\Contracts\PoolerProbe;
use Pushery\SQLens\Contracts\ReplicaProbe;
use Pushery\SQLens\Contracts\ShadowProvisioner;
use Pushery\SQLens\Contracts\ShadowRunner;
use Pushery\SQLens\Exceptions\ShadowProvisioningUndetermined;
use Pushery\SQLens\Exceptions\ShadowTeardownIncomplete;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Subjects\CaptureMode;
use Throwable;

/**
 * The truth-mode captor: it runs the pending migrations for real against a
 * throwaway database and captures the SQL they emit — the same `CaptureResult`
 * shape the pretend path produces, because there is exactly one data path into
 * the rule engine, never a second.
 *
 * This class is the ORCHESTRATOR and holds no database knowledge of its own. It
 * sequences guard → provision → run → teardown and delegates each step:
 *
 *   - The **production guard** decision is made by the command and handed in. The
 *     captor never provisions on a blocked decision — a mode that creates and
 *     drops databases must be UNREACHABLE without the guard, and this is where
 *     that is enforced. A blocked run is undetermined, never a pass.
 *   - The **provisioner** creates and drops the shadow database; the captor knows
 *     only the `ShadowProvisioner` interface, so no `CREATE DATABASE` or `TEMPLATE`
 *     lives here. A null provisioner means the driver is unsupported (MariaDB,
 *     SQLite) — a named `undetermined`, never a silent fallback to pretend.
 *   - The **runner** performs the real migrate-and-capture; the captor turns its
 *     run into the final result.
 *
 * Teardown is guaranteed: the shadow database is dropped in a `finally`, so a
 * failure mid-run still cleans up — unless `keep_on_failure` is set, the one case
 * where a failed run's database is deliberately kept for debugging.
 */
final readonly class ShadowCaptor implements Captor
{
    public function __construct(
        private GuardDecision $decision,
        private ?ShadowProvisioner $provisioner,
        private ShadowRunner $runner,
        private bool $keepOnFailure = false,
        private ?ReplicaProbe $replicaProbe = null,
        private string $connectionName = '',
        private ?PoolerProbe $poolerProbe = null,
        private bool $hasDirectConnection = false,
        private bool $directConnectionElsewhere = false,
        private bool $roundtrip = false,
        private ?ShadowOrphanSweeper $sweeper = null,
    ) {}

    public function capture(iterable $migrations, CaptureSection $section): CaptureRun
    {
        $pending = array_values(is_array($migrations) ? $migrations : iterator_to_array($migrations, false));

        // The guard is the first gate: a blocked decision never reaches a
        // provisioner, so a database is never created for a run that may not run.
        if ($this->decision->isBlocked()) {
            return $this->allUndetermined($pending, $section, UndeterminedReason::ShadowGuardBlocked);
        }

        // An unsupported engine is a named undetermined, never a quiet fall back to
        // the pretend path — declared non-goals produce a clear result, not half a
        // shadow run.
        if (! $this->provisioner instanceof ShadowProvisioner) {
            return $this->allUndetermined($pending, $section, UndeterminedReason::UnsupportedEngine);
        }

        // A read replica has a different state than its primary and forbids the
        // writes provisioning needs. Detected BEFORE any database is created, so a
        // replica target is a named undetermined, never a run against the wrong
        // instance. The probe is a read; when none is wired, there is nothing to
        // detect and the flow proceeds.
        if ($this->replicaProbe instanceof ReplicaProbe && $this->replicaProbe->isReplica($this->connectionName)) {
            return $this->allUndetermined($pending, $section, UndeterminedReason::TargetIsReplica);
        }

        // A direct connection pointed at ANOTHER server is refused before the pooler
        // question is even asked, because it is the more dangerous of the two: a pooled
        // source costs a failed run, while provisioning on an instance nobody named
        // creates and drops databases somewhere the operator is not looking. Decided
        // from configuration alone — no connection is opened to find out, so the check
        // cannot itself become a reason the run stops.
        if ($this->directConnectionElsewhere) {
            return $this->allUndetermined($pending, $section, UndeterminedReason::ShadowDirectConnectionElsewhere);
        }

        // A transaction pooler (PgBouncer) breaks the template operations
        // provisioning needs. When a direct connection is configured it is used and
        // no probe is needed; otherwise the source is checked, and a pooled source
        // stops the run BEFORE any DDL — with an actionable reason, never a failed
        // CREATE DATABASE. The check is heuristic and named one in the reason.
        if (! $this->hasDirectConnection
            && $this->poolerProbe instanceof PoolerProbe
            && $this->poolerProbe->isTransactionPooled($this->connectionName)) {
            return $this->allUndetermined($pending, $section, UndeterminedReason::ShadowTransactionPooling);
        }

        // The net for the one teardown path a `try/finally` cannot cover — the two comments further
        // down in this file name it twice. A process killed mid-run never reaches its own cleanup,
        // so what it leaked is removed by a LATER run, and this is that run.
        //
        // AFTER the guard and BEFORE provisioning, and both halves are load-bearing. After the
        // guard, because dropping a database is a database-mutating action and a blocked run may
        // take none. Before provisioning, because this run's own throwaway database is younger than
        // any threshold and must never become a candidate for its own sweep.
        //
        // A failure here does not end the run. The sweeper already keeps one obstinate database from
        // stopping the rest, and what it could not remove stays visible in its report; what is left
        // to fail at this level is the LISTING, which is a statement about somebody else's leftovers
        // rather than about the migrations this run was asked to capture. The next run tries again.
        if ($this->sweeper instanceof ShadowOrphanSweeper) {
            try {
                $this->sweeper->sweep($this->decision, new DateTimeImmutable('now', new DateTimeZone('UTC')));
            } catch (Throwable) {
                // Deliberate, and bounded to the sentence above: this run's verdict is about its own
                // migrations. An orphan nobody could list is still an orphan, and the sweep that
                // runs before the next capture is where it is tried again.
            }
        }

        // The provisioner may stop on an engine-specific precondition — no CREATEDB
        // privilege, a busy template, a name collision — that it can only see once it
        // reaches the server. Those are named undetermineds rather than failures, and each
        // says why.
        //
        // "Nothing was created" is the promise, and it is worth stating precisely because it
        // used to be false: on PostgreSQL the provisioner builds a TEMPLATE database before
        // it can meet two of those three preconditions, and a throw after that point left it
        // on the server — the project's whole schema, under a name nothing would collect.
        // `destroy()` discards the template, but it takes a ShadowSession and a refused run
        // has none. The provisioner now discards it on every path out, so what the caller
        // sees is what this comment claims: nothing REMAINS.
        //
        // Any OTHER throwable from provisioning is a real failure and propagates.
        try {
            $session = $this->provisioner->provision();
        } catch (ShadowProvisioningUndetermined $undetermined) {
            return $this->allUndetermined($pending, $section, $undetermined->reason);
        }

        try {
            $run = $this->roundtrip
                ? $this->captureRoundtrip($session, $pending)
                : $this->runner->captureFrom($session, $pending, $section);
        } catch (Throwable $throwable) {
            // A failed run: drop the throwaway database (best effort — the original
            // throwable is the signal to surface, and the orphan sweep is the net for
            // a drop that also fails), unless keep_on_failure keeps it for debugging.
            if (! $this->keepOnFailure) {
                try {
                    $this->provisioner->destroy($session);
                } catch (Throwable) {
                    // Swallowed on purpose here: the run's own throwable must reach the
                    // caller. A leaked database from this path is removed by the orphan
                    // sweep, which lists databases carrying our prefix.
                }
            }

            throw $throwable;
        }

        // A successful run: drop the throwaway database. A drop that FAILS is never
        // swallowed — a database nobody removes is a leak — so it is surfaced as an
        // extra undetermined result naming the leaked database.
        try {
            $this->provisioner->destroy($session);
        } catch (Throwable $failure) {
            return CaptureRun::of(
                [...$run->results, ...$this->teardownFailures($session, $section, $failure)],
                $this->mode(),
            );
        }

        return $run;
    }

    /**
     * The roundtrip: `up`, then `down`, then `up` again — all against the SAME
     * throwaway database, which is the only way the question makes sense. Running
     * each leg against its own clone would prove nothing about reversibility; the
     * point is whether the second `up` still works on the state `down` left behind.
     *
     * `down` runs in REVERSE order. Migrations undo in the opposite order they
     * applied, and a `down` that dropped a table another migration's `down` still
     * references would fail for the wrong reason.
     *
     * A leg that fails stops the roundtrip: once `down` has failed, the database is
     * in a state the second `up` cannot be judged against, so running it anyway
     * would produce a failure nobody could attribute. The legs that did run are
     * kept — they are the evidence — and the sections tell them apart.
     *
     * @param  list<PendingMigration>  $pending
     */
    private function captureRoundtrip(ShadowSession $session, array $pending): CaptureRun
    {
        $results = [];

        foreach ([CaptureSection::Up, CaptureSection::Down, CaptureSection::UpAgain] as $leg) {
            $migrations = $leg === CaptureSection::Down ? array_reverse($pending) : $pending;
            $run = $this->runner->captureFrom($session, $migrations, $leg);
            $results = [...$results, ...$run->results];

            // A leg that did not come through clean ends the roundtrip. The next leg
            // would run against a state nobody can reason about.
            foreach ($run->results as $result) {
                if ($result->isFail() || $result->isUndetermined()) {
                    return CaptureRun::of($results, $this->mode());
                }
            }
        }

        return CaptureRun::of($results, $this->mode());
    }

    /**
     * One result per database still on the server, named.
     *
     * Each carries the `ShadowTeardownFailed` reason and names the leaked database as its "file", so
     * a reader can remove it by hand. It rides as an extra RESULT rather than a new run-level field:
     * that way the existing three-valued aggregation counts a leaked database as an undetermined the
     * run must answer for, instead of needing a fourth thing for a caller to remember to read.
     *
     * It used to be one result naming `$session->shadowDatabase` — the CLONE — whatever had
     * actually failed. On PostgreSQL a shadow run creates two databases, and the one that leaks is
     * more often the template: it is dropped second, so a clone whose drop threw took it down with
     * it. A reader following that report went looking for a database that was already gone, while
     * the one still sitting there — carrying the project's whole schema — was never mentioned.
     *
     * A teardown that knows what it left behind says so. One that does not falls back to the
     * session's own database, which is the best it can name.
     *
     * @return list<CaptureResult>
     */
    private function teardownFailures(ShadowSession $session, CaptureSection $section, Throwable $failure): array
    {
        $leaked = $failure instanceof ShadowTeardownIncomplete
            ? $failure->leaked()
            : [$session->shadowDatabase];

        return array_map(
            fn (string $database): CaptureResult => CaptureResult::undetermined(
                $database,
                'ShadowTeardown',
                $section,
                $this->mode(),
                UndeterminedReason::ShadowTeardownFailed,
            ),
            $leaked,
        );
    }

    public function mode(): CaptureMode
    {
        return CaptureMode::Shadow;
    }

    /**
     * Every pending migration as an undetermined result for the same reason — the
     * honest shape of a run that could not even begin (guard-blocked or
     * unsupported): nothing was captured, and each migration says why.
     *
     * @param  list<PendingMigration>  $pending
     */
    private function allUndetermined(array $pending, CaptureSection $section, UndeterminedReason $reason): CaptureRun
    {
        $results = array_map(
            fn (PendingMigration $migration): CaptureResult => CaptureResult::undetermined(
                $migration->file,
                $migration->migrationClass,
                $section,
                $this->mode(),
                $reason,
            ),
            $pending,
        );

        return CaptureRun::of($results, $this->mode());
    }
}
