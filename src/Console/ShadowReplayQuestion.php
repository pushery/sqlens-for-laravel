<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Illuminate\Contracts\Config\Repository;
use Pushery\SQLens\Capture\Shadow\ShadowProvisioningConnection;

/**
 * The question `sqlens:drift` and `sqlens:postdeploy --expect-shadow` ask before the shadow replay
 * creates and drops its reference database.
 *
 * It names the connection that happens on when that is not the one being compared. With
 * `capture.shadow.connection` or `capture.shadow.direct_connection` set, the reference database is
 * built there, and a question naming only the compared connection would ask for consent to create a
 * database on a server it never mentions.
 */
final readonly class ShadowReplayQuestion
{
    public static function for(Repository $config, string $connectionName): string
    {
        $provisioning = ShadowProvisioningConnection::for($config, $connectionName);

        return $provisioning === $connectionName
            ? 'Run the shadow replay against '.$connectionName.'?'
            : 'Run the shadow replay against '.$connectionName.'? Its throwaway database is created and dropped on the '.$provisioning.' connection.';
    }
}
