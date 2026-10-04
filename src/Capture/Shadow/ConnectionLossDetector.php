<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

use Illuminate\Database\DetectsLostConnections;
use Throwable;

/**
 * Recognizes a shadow session the SERVER ended, so the run reports it as `undetermined`
 * (`shadow_connection_lost`) rather than as a failure of the migration it was running.
 *
 * A backend an operator terminates, a server that restarts and a network that drops all end a
 * migration mid-statement, and none of them says anything about the migration. Measured with a
 * PostgreSQL backend ended mid-migration: the run reported `CAP.L0.MIGRATE_ERROR`, "no connection to
 * the server", a failure of a migration that may well be sound.
 *
 * The decision is Laravel's own. `DetectsLostConnections` is what a connection asks before it
 * reconnects, so one list of what a lost connection looks like serves every engine and framework
 * version the package supports. Both shapes PostgreSQL 18 produced through Laravel's connection are
 * on it: `server closed the connection unexpectedly` outside a transaction, and `no connection to
 * the server` inside one, where the failed rollback is what surfaces.
 */
final readonly class ConnectionLossDetector
{
    use DetectsLostConnections;

    public static function isConnectionLoss(Throwable $throwable): bool
    {
        return (bool) new self()->causedByLostConnection($throwable);
    }
}
