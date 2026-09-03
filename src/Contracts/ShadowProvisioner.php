<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Capture\Shadow\ShadowSession;

/**
 * The per-driver contract for creating and removing a throwaway shadow database —
 * the one place the engine-specific way of cloning a schema lives.
 *
 * PostgreSQL clones with `CREATE DATABASE … TEMPLATE`; MySQL has no template and
 * rebuilds from a schema dump. Neither of those SQL fragments may leak into the
 * neutral `ShadowCaptor`, so the captor talks only to this interface and the
 * concrete provisioners hold the driver knowledge — the same split that keeps the
 * core+driver separation a mechanical move.
 *
 * A provisioner is reached ONLY after the production guard has allowed the run.
 * That ordering is the captor's responsibility, stated here because it is the
 * whole safety story: a mode that creates and drops databases must never be
 * reachable without the guard, and `provision()` trusts that it was.
 */
interface ShadowProvisioner
{
    /** Whether this provisioner handles the given driver key (`pgsql`, `mysql`). */
    public function supports(string $driver): bool;

    /**
     * Create the throwaway database and register a connection pointing at it,
     * returning the session that names both. The caller drops it afterwards by
     * passing the session back to destroy().
     */
    public function provision(): ShadowSession;

    /**
     * Remove the throwaway database named by the session and release its
     * connection. Idempotent and defensive: a teardown that runs after a partial
     * provisioning, or twice, must not throw — a database nobody drops is a leak in
     * the user's environment, so this errs toward always cleaning up.
     */
    public function destroy(ShadowSession $session): void;
}
