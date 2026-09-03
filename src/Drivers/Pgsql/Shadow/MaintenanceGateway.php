<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Shadow;

/**
 * The narrow set of catalog reads and DDL the PostgreSQL shadow provisioner needs
 * from a maintenance connection (one attached to an admin database such as
 * `postgres`, never the template being cloned).
 *
 * It exists as a port so the provisioner's ORCHESTRATION — the order of the
 * precondition checks and the three-valued outcome each produces — can be tested
 * deterministically against a fake, while the concrete `ConnectionMaintenanceGateway`
 * carries the real SQL and is proven against a live `postgres:18`. Neither side
 * knows the other's job: no `CREATE DATABASE` string lives in the provisioner, and
 * no undetermined-reason logic lives in the gateway.
 *
 * Every method here is either a read or a create/drop of a database that carries
 * the shadow prefix — the gateway never touches a database it was not told to, and
 * never writes to one.
 */
interface MaintenanceGateway
{
    /**
     * Whether the current role may create databases — PostgreSQL's `CREATEDB`
     * attribute, which a superuser also satisfies. Checked before any clone is
     * attempted so a role that cannot provision produces a named result, not a
     * mid-run permission error.
     */
    public function canCreateDatabase(): bool;

    /**
     * The number of active connections to $database OTHER than this maintenance
     * connection. A non-zero count means PostgreSQL will refuse the database as a
     * `CREATE DATABASE … TEMPLATE` source, so it is read before the clone rather
     * than discovered by a failed template operation.
     */
    public function activeConnectionCount(string $database): int;

    /**
     * WHO those connections are, for the refusal message — never for a decision.
     *
     * The count above answers "may this be cloned"; this answers the question a reader asks
     * next and nothing else could: WHICH session is in the way. A refusal that says only "the
     * template has other active connections" is a named reason with nowhere to go, and this
     * package's own rule is that a reason you cannot look up is half a reason.
     *
     * ## The one field this deliberately does NOT read
     *
     * `pg_stat_activity.query` is the obvious thing to include and is excluded on purpose. A
     * running statement can carry a credential — the very thing `SEC.AUTH.PASSWORD_LITERAL_*`
     * exists to keep out of a report — and this string travels into an exception message that
     * may reach a log, a CI transcript or a terminal. `pid`, `application_name`, `state` and
     * `backend_start` identify a session well enough to go and look at it, and none of them
     * can carry a value the session was handling.
     *
     * Best-effort by contract: an implementation that cannot read the view returns an empty
     * list, and the caller says how many it counted rather than pretending it knows who.
     *
     * @return list<array{pid: int, application_name: string, state: string, backend_start: string}>
     */
    public function describeActiveConnections(string $database): array;

    /** Whether a database named $name already exists in `pg_database`. */
    public function databaseExists(string $name): bool;

    /**
     * Create $name as an EMPTY database, cloned from `template0` — PostgreSQL's
     * pristine template, which carries no user objects and no rows at all.
     *
     * This is how a virgin template starts: `template1` is the default source and a
     * site may have added objects to it, so it is deliberately not used. The schema
     * is replayed into the result afterwards; what matters here is that the database
     * begins with nothing in it.
     */
    public function createEmptyDatabase(string $name): void;

    /**
     * Clone $template into a new database $shadow via `CREATE DATABASE … TEMPLATE`,
     * outside any transaction (template operations are not transactional). Both
     * identifiers are quoted; the shadow name is generated from `[a-z0-9_]` and the
     * template name comes from configuration.
     */
    public function createDatabaseFromTemplate(string $shadow, string $template): void;

    /**
     * Drop $name with `DROP DATABASE IF EXISTS … WITH (FORCE)` — idempotent (a name
     * already gone is not an error) and forceful (any lingering session on the
     * throwaway database is terminated), so teardown always succeeds in removing it.
     */
    public function dropDatabase(string $name): void;
}
