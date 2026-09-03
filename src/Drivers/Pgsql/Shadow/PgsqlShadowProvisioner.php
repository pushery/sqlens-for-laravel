<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Shadow;

use Closure;
use DateTimeImmutable;
use DateTimeZone;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Support\Sleep;
use Pushery\SQLens\Capture\Shadow\ShadowSession;
use Pushery\SQLens\Contracts\ShadowProvisioner;
use Pushery\SQLens\Exceptions\ShadowProvisioningUndetermined;
use Pushery\SQLens\Exceptions\ShadowTeardownIncomplete;
use Pushery\SQLens\Findings\UndeterminedReason;
use Throwable;

/**
 * The PostgreSQL side of the truth mode: a throwaway database cloned from the
 * source via `CREATE DATABASE … TEMPLATE`, and dropped again on teardown.
 *
 * It is the ORCHESTRATOR of provisioning and holds no SQL of its own — every
 * catalog read and every DDL goes through the {@see MaintenanceGateway} port, so
 * the precondition ordering and the three-valued outcomes are testable against a
 * fake while the real SQL is proven against a live server. The order is the whole
 * safety story:
 *
 *   1. The role must be able to create a database (`CREATEDB`). If not, the run is
 *      undetermined — never a raw permission error surfacing mid-clone.
 *   2. The generated name must be free. If a database by that name already exists,
 *      the run stops rather than touch a database it did not create — the shadow
 *      mode only ever creates and drops databases carrying its own prefix.
 *   3. The template must have no other active connections, or PostgreSQL refuses it
 *      as a `TEMPLATE` source. Read from `pg_stat_activity`, not discovered by a
 *      failed clone.
 *
 * THE ORDER IS SORTED CHEAPEST-AND-MOST-DETERMINISTIC FIRST, and that is a decision
 * rather than a convenience. Checks 1 and 2 are single catalog reads whose answers do
 * not change with how busy the machine is; check 3 is a timing question about a
 * backend on its way out. With 3 ahead of 2 — where it used to be — a run that was
 * going to refuse on a name collision could instead refuse for a busy template, so the
 * REASON the user was given depended on load. It also meant a run refused on a name
 * had already built a template holding the project's whole schema, to answer a
 * question one catalog read settles.
 *
 * Only when all three hold is `CREATE DATABASE … TEMPLATE` issued and a runtime
 * connection to the clone registered. Encoding, collation, and locale are inherited
 * from the template and never overridden.
 *
 * WHAT THE TEMPLATE MAY BE is the load-bearing part. `CREATE DATABASE … TEMPLATE`
 * copies its source byte for byte — every row of it — and none of the three checks
 * above asks about rows, because none of them can. The safety therefore does not
 * live in this class at all: the template arrives as a {@see VirginTemplate}, a
 * value that can only be minted after its rows have been COUNTED and found to be
 * none. A caller cannot hand this provisioner the live database by passing a
 * different string, because it does not accept a string.
 *
 * A provisioner is reached ONLY after the production guard has allowed the run and
 * the captor has ruled out a replica and a transaction pooler; those engine-neutral
 * checks are the captor's. These three are the engine-specific preconditions only
 * PostgreSQL can answer, so they live here.
 */
final readonly class PgsqlShadowProvisioner implements ShadowProvisioner
{
    /** How many times the template's connection count is read before it counts as in use. */
    private const int IDLE_READS = 3;

    /** The pause between those reads — small, and only ever spent on the way to a refusal. */
    private const int IDLE_RETRY_MICROSECONDS = 50_000;

    /**
     * @param  Closure(): string  $nameFactory  produces a fresh shadow database name
     * @param  array<string, mixed>  $shadowConnectionConfig  the connection config the clone is registered under, its `database` replaced by the shadow name
     */
    public function __construct(
        private MaintenanceGateway $gateway,
        private Repository $config,
        private DatabaseManager $db,
        private Closure $nameFactory,
        private array $shadowConnectionConfig,
        private PgsqlVirginTemplateBuilder $templates,
        private string $sourceConnection,
    ) {}

    public function supports(string $driver): bool
    {
        return $driver === 'pgsql';
    }

    public function provision(): ShadowSession
    {
        $name = ($this->nameFactory)();

        if (! $this->gateway->canCreateDatabase()) {
            throw new ShadowProvisioningUndetermined(UndeterminedReason::ShadowInsufficientPrivileges);
        }

        // Never adopt a database we did not create: a name collision stops the run.
        //
        // ⚠️ IT IS CHECKED BEFORE THE TEMPLATE IS BUILT, and the order is load-bearing twice over.
        //
        // It is the CHEAPEST and the most DETERMINISTIC of the refusals — one catalog read about a
        // name — and it used to sit behind `waitForIdle()`, which is neither. So on a busy server
        // the run refused with `ShadowTemplateInUse` for a name that was going to collide anyway:
        // the honest reason lost a race to a timing-sensitive one, and the reported cause depended
        // on how loaded the machine was. Measured as an intermittent CI failure where a test
        // staging a collision was told the template was in use instead.
        //
        // And it means a run refused on a name no longer builds a template first. That build
        // creates a database holding the project's entire schema — expensive, and one more thing
        // to have to remove — to answer a question that needed a catalog read.
        if ($this->gateway->databaseExists($name)) {
            throw new ShadowProvisioningUndetermined(UndeterminedReason::ShadowNameCollision);
        }

        // The template is built HERE, not handed in already built, and that is
        // deliberate: building one CREATES a database, so doing it in a constructor
        // would provision for a run the guard may still refuse. Inside provision() the
        // guard has already allowed the run, and a build that cannot finish surfaces as
        // the named undetermined the captor knows how to report.
        $template = $this->templates->build();

        // EVERYTHING after the build is guarded, because the build CREATED a database and every path
        // below can leave without one.
        //
        // `destroy()` discards the template — but it takes a ShadowSession, and on a throw path there
        // is none, so it never runs. A refused run therefore used to leave the project's ENTIRE
        // SCHEMA sitting on the server under a name nothing would ever collect. That is a direct
        // primum-non-nocere failure, and it was invisible: the tests that exercised these paths
        // asserted the CLONE was absent and then dropped the template themselves, one line later.
        //
        // The catch is `Throwable` rather than the two named refusals: `createDatabaseFromTemplate()`
        // can fail for reasons this class does not enumerate — a disk that filled, a connection that
        // died — and a leak is a leak whatever threw.
        try {
            // The template must be idle: PostgreSQL refuses a database with other active
            // connections as a TEMPLATE source. Read it rather than fail the clone.
            if (! $this->waitForIdle($template->database)) {
                // Name them here or never: this is the last moment those sessions are observable.
                // Once the exception is caught the reason enum is all that survives, and a CI
                // failure that says only "other active connections" sends the next reader back to
                // a server whose state has moved on.
                throw new ShadowProvisioningUndetermined(
                    UndeterminedReason::ShadowTemplateInUse,
                    $this->describeBlockers($template->database),
                );
            }

            $this->gateway->createDatabaseFromTemplate($name, $template->database);

            $this->registerConnection($name);
        } catch (Throwable $failure) {
            // Discarded here and NOT swallowed: the caller still gets its named undetermined, which
            // is what the captor reports. The cleanup is silent about its own errors for the same
            // reason `destroy()` is — a teardown that throws while unwinding replaces a diagnosable
            // failure with an undiagnosable one.
            try {
                $this->templates->discard($template->database);
            } catch (Throwable) {
                // Nothing to add: the original failure below is the one worth reporting.
            }

            throw $failure;
        }

        return new ShadowSession(
            $name,
            $name,
            $this->sourceConnection,
            new DateTimeImmutable('now', new DateTimeZone('UTC')),
            $template->database,
        );
    }

    public function destroy(ShadowSession $session): void
    {
        // Release our own connection to the throwaway database first so nothing of
        // ours is left holding it, then drop it. The drop is IF EXISTS … WITH
        // (FORCE), so a database already gone (a teardown that runs twice, or after a
        // partial provisioning) is not an error and any stray session is terminated —
        // a database nobody drops is a leak, so this errs toward always removing it.
        $this->db->purge($session->connectionName);

        // EVERY database this run created is attempted, whatever happened to the one before it.
        //
        // This used to be two statements in a row, and the order was the bug: a clone whose drop
        // threw took the TEMPLATE's drop with it, and the template is the worse leak by a distance
        // — it carries the project's whole schema. Under a busy server that is not hypothetical, it
        // is the ordinary failure: a `DROP DATABASE` can succeed on the server and still raise on
        // the client when the link dies reading the result, which leaves exactly the state that was
        // measured in CI — the clone gone, the template still there, and nothing said about it.
        //
        // The failures are collected rather than rethrown at the first one for the same reason:
        // whichever database is still on the server has to be NAMED, and the first exception can
        // only name one of them.
        $failures = [];

        try {
            $this->gateway->dropDatabase($session->shadowDatabase);
        } catch (Throwable $failure) {
            $failures[$session->shadowDatabase] = $failure;
        }

        // The TEMPLATE goes too. A shadow run on PostgreSQL creates two databases, and
        // a template left behind is the same leak as a clone left behind — worse, in
        // fact, since it carries the project's whole schema.
        if ($session->templateDatabase !== null) {
            try {
                $this->templates->discard($session->templateDatabase);
            } catch (Throwable $failure) {
                $failures[$session->templateDatabase] = $failure;
            }
        }

        if ($failures !== []) {
            throw ShadowTeardownIncomplete::for($failures);
        }
    }

    /**
     * Register a runtime connection pointing at the throwaway database, under the
     * shadow name, so the runner can migrate and capture against it. The config is
     * the caller-supplied template with `database` swapped to the clone.
     */
    private function registerConnection(string $name): void
    {
        $this->config->set('database.connections.'.$name, [
            ...$this->shadowConnectionConfig,
            'database' => $name,
        ]);

        // Clear any cached resolution under this name so the next resolve builds the
        // connection fresh from the config just written.
        $this->db->purge($name);
    }

    /**
     * The refusal's diagnosis: who holds $database, in one line.
     *
     * Read AFTER the wait rather than during it, and that ordering is the point. A session
     * observed on the first of three reads may be a backend on its way out — the very thing the
     * wait exists to tolerate — so describing it would name a session that is no longer the
     * reason for anything. What is left standing after ~100 ms is what actually blocks.
     *
     * A gateway that cannot read the view answers with an empty list, and then this says how many
     * were counted instead of inventing a who. "3 sessions, none of them readable" is a true
     * sentence and a useful one; a blank is neither.
     */
    private function describeBlockers(string $database): string
    {
        $sessions = $this->gateway->describeActiveConnections($database);

        if ($sessions === []) {
            return sprintf(
                'Holders: %d session(s), not describable by this role.',
                $this->gateway->activeConnectionCount($database),
            );
        }

        return 'Holders: '.implode('; ', array_map(
            static fn (array $session): string => sprintf(
                'pid %d %s (%s, since %s)',
                $session['pid'],
                $session['application_name'] === '' ? '<unnamed>' : $session['application_name'],
                $session['state'],
                $session['backend_start'],
            ),
            $sessions,
        )).'.';
    }

    /**
     * Whether the template is idle — re-read a few times before concluding it is not.
     *
     * The builder closes its own connection to the template before handing it over (it has to; a
     * template with any other connection cannot be cloned). But closing a client connection and the
     * SERVER reaping its backend are two different events: `pg_stat_activity` can still list a backend
     * that is on its way out, and that window is exactly as long as the machine is busy.
     *
     * Measured as an intermittent CI failure where `provision()` refused its OWN freshly built
     * template — never locally, always under load. A single read is a hair-trigger on a race this
     * class caused itself, and the honest question is not "is a row there right now" but "is anyone
     * still using this". A backend on its way out is not.
     *
     * The budget is tiny and only ever spent on the way to a refusal: three reads over ~100 ms. A
     * template that is genuinely in use stays in use, and the run still refuses.
     */
    private function waitForIdle(string $database): bool
    {
        for ($attempt = 0; $attempt < self::IDLE_READS; $attempt++) {
            if ($this->gateway->activeConnectionCount($database) === 0) {
                return true;
            }

            Sleep::usleep(self::IDLE_RETRY_MICROSECONDS);
        }

        return false;
    }
}
