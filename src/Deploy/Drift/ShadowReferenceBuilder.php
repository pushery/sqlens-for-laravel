<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

use Pushery\SQLens\Capture\CaptureSection;
use Pushery\SQLens\Capture\PendingMigration;
use Pushery\SQLens\Capture\Shadow\GuardDecision;
use Pushery\SQLens\Catalog\CatalogReaderFactory;
use Pushery\SQLens\Catalog\CatalogRequest;
use Pushery\SQLens\Catalog\ReaderConnectionFactory;
use Pushery\SQLens\Contracts\ShadowProvisioner;
use Pushery\SQLens\Contracts\ShadowRunner;
use Pushery\SQLens\Exceptions\ShadowProvisioningUndetermined;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Subjects\SubjectContext;
use Throwable;

/**
 * The EXPECTATION side of a drift comparison, built by replaying the migration state into a
 * throwaway database and reading the schema back out of it.
 *
 * Why a replay rather than a dump file: a dump is a claim about what the migrations produce, made
 * at the moment somebody last regenerated it. A replay is the migrations themselves, run by the
 * same framework that will run them in production. The two disagree exactly when it matters most —
 * after a migration was edited, or added, and the dump was not refreshed.
 *
 * This class ORCHESTRATES and holds no database knowledge, the same division {@see ShadowCaptor}
 * draws: guard → provision → replay → read → teardown, each step delegated. No `CREATE DATABASE`,
 * no catalog SQL and no driver name appears here.
 *
 * ## The request is handed IN, never built here
 *
 * A drift report compares two catalogs, and a difference between them is only meaningful if both
 * were asked the SAME question — the same schemas, the same object types, the same table prefix and
 * prefix scope. A builder that assembled its own {@see CatalogRequest} would be a second place where
 * that question is decided, and the day the two drift apart the comparison starts inventing findings
 * out of its own configuration. So the caller reads both sides with one request, and this signature
 * makes that the only thing it can do.
 *
 * ## Teardown is guaranteed, and the guard runs before anything exists to tear down
 *
 * The throwaway database is dropped in a `finally`, so a replay that throws still cleans up. A
 * blocked guard decision returns before a provisioner is ever asked for a database — a mode that
 * creates and drops databases has to be UNREACHABLE without the guard, not merely refused after the
 * fact.
 */
final readonly class ShadowReferenceBuilder
{
    public function __construct(
        private ?ShadowProvisioner $provisioner,
        private ShadowRunner $runner,
        private ReaderConnectionFactory $connections,
        private CatalogReaderFactory $readers,
        private string $sourceConnection,
        private string $sourceDatabase,
        private string $driver,
        private bool $keepOnFailure = false,
    ) {}

    /**
     * Replay the migration state into a shadow database and read its catalog.
     *
     * @param  iterable<PendingMigration>  $migrations  the pending migrations, in the order they would run
     */
    public function build(
        GuardDecision $decision,
        iterable $migrations,
        CatalogRequest $request,
        SubjectContext $context,
    ): ShadowReferenceOutcome {
        // First gate, and it is first for a reason: nothing below may create a database for a run
        // that was not allowed to run at all.
        if ($decision->isBlocked()) {
            return ShadowReferenceOutcome::undetermined(UndeterminedReason::ShadowGuardBlocked);
        }

        // An engine with no provisioner is a declared non-goal (MariaDB, SQLite). Named, never a
        // quiet fall back to reading the live database as its own expectation — which would compare
        // a catalog against itself and report a clean result forever.
        if (! $this->provisioner instanceof ShadowProvisioner) {
            return ShadowReferenceOutcome::undetermined(UndeterminedReason::UnsupportedEngine);
        }

        // Provisioning refuses with a NAMED reason, and that reason is the answer — not a crash.
        //
        // It sat outside this catch and escaped the command as an uncaught exception, so a project
        // with no committed schema dump — the commonest case there is, and the one every first run
        // meets — got a stack trace where a sentence belongs. Everything else in this class already
        // returns `undetermined` with a reason; this was the one path that did not, and it is the
        // likeliest of them all to be taken. Found by the first test that ran the command against a
        // real server without a dump.
        try {
            $session = $this->provisioner->provision();
        } catch (ShadowProvisioningUndetermined $refusal) {
            return ShadowReferenceOutcome::undetermined($refusal->reason);
        }

        $failed = false;

        try {
            $run = $this->runner->captureFrom($session, $migrations, CaptureSection::Up);

            // A replay that did not come through clean produces a schema nobody can reason about:
            // some migrations applied, some not, and no way to tell which half the reader is
            // looking at. Comparing the live database against THAT would report differences the
            // migrations never asked for. Named as a failed replay rather than returned as a
            // partial expectation.
            foreach ($run->results as $result) {
                if ($result->isFail() || $result->isUndetermined()) {
                    $failed = true;

                    return ShadowReferenceOutcome::undetermined(UndeterminedReason::ShadowMigrateFailed);
                }
            }

            $connection = $this->connections->forShadowDatabase($this->sourceConnection, $session->shadowDatabase);

            $snapshot = $this->readers
                ->for($this->driver, $connection, $this->connections->budget(), $context)
                ->catalog
                ->read($request);

            // The throwaway database's name comes back OUT before anything compares it. On MySQL the
            // schema is the database, so every qualified name would otherwise carry it and the two
            // sides could never meet — measured on the first MySQL run: one undescribed table
            // produced 44 unexpected and 24 missing findings, and two runs disagreed because the
            // shadow name carries a timestamp.
            return ShadowReferenceOutcome::of(
                ShadowSchemaRewrite::apply($snapshot, $session->shadowDatabase, $this->sourceDatabase),
                $session->shadowDatabase,
            );
        } catch (Throwable $failure) {
            $failed = true;

            throw $failure;
        } finally {
            // `keep_on_failure` is the one case where a failed run's database is deliberately left
            // standing, for a person to look inside. A SUCCESSFUL run is always torn down: keeping
            // it would leave the project's whole schema on the server with nobody watching.
            if (! $failed || ! $this->keepOnFailure) {
                $this->provisioner->destroy($session);
            }
        }
    }
}
