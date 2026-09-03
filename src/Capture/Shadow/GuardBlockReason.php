<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

/**
 * Why the production guard held a database-creating run — never a bare boolean.
 *
 * A blocked run is undetermined, and an undetermined is never anonymous: the
 * report says WHICH check refused it, because the fix differs. A disallowed
 * environment is a configuration decision; a production connection is a target
 * mistake; a missing confirmation is a one-flag fix. Collapsing them into "not
 * allowed" would leave a user guessing which.
 *
 * The backed values reach the run header and are a stable part of the output.
 */
enum GuardBlockReason: string
{
    /** The current environment is not on the allowed list — not overridable by --force. */
    case DisallowedEnvironment = 'disallowed_environment';

    /** The target connection is marked as a production connection. */
    case ProductionConnection = 'production_connection';

    /** An interactive run the user did not confirm, or a non-interactive run without --force. */
    case NotConfirmed = 'not_confirmed';

    /** A one-line English explanation of the block, for the run header. */
    public function description(): string
    {
        return match ($this) {
            self::DisallowedEnvironment => 'The shadow mode may only run in an allowed environment, and this one is not on the list.',
            self::ProductionConnection => 'The target connection is a production connection, which a database-creating mode must never run against.',
            self::NotConfirmed => 'The run was not confirmed: pass --force, or run interactively and confirm.',
        };
    }
}
