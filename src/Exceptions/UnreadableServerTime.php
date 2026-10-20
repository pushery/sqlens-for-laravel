<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use RuntimeException;

/**
 * The database server did not answer with its current time.
 *
 * A shadow database is named with the server's time when a run creates it, and a later run's orphan
 * sweep ages it against the server's time. Neither falls back to the local clock: a machine whose
 * clock runs behind would stamp a database that a sweep on another machine takes for an old one, and
 * the sweep drops what it takes for old.
 */
final class UnreadableServerTime extends RuntimeException
{
    public function __construct()
    {
        parent::__construct(
            'The database server did not report its current time as a UTC timestamp (YYYYMMDDHHMMSS), '
            .'which a shadow database is named by and a later run ages it by.',
        );
    }
}
