<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

use Laravel\Mcp\Server;

/**
 * Whether the optional server SDK is installed in this application.
 *
 * Asked by the class the server is built on, which is what serving needs. Which release is
 * installed is the other question, answered by {@see McpSdkVersion}.
 */
final readonly class McpSdkAvailability
{
    /**
     * The class is a parameter so a test can reach the branch for an SDK that is not installed;
     * inside this suite the SDK always is.
     */
    public static function check(string $serverClass = Server::class): bool
    {
        return class_exists($serverClass);
    }
}
