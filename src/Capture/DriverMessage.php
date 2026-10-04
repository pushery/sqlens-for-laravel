<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Illuminate\Database\QueryException;
use Throwable;

/**
 * The database's own words for a failure, without Laravel's account of where it happened.
 *
 * Laravel wraps a failed query in a `QueryException` whose message appends the connection name, the
 * host, port and database it reached, and the statement with every binding written in. The PDO
 * exception inside it carries the SQLSTATE and the driver's text, and that is what a finding quotes:
 * the masks a capture rule applies can then work on the driver's sentence alone.
 */
final readonly class DriverMessage
{
    public static function of(Throwable $throwable): string
    {
        return $throwable instanceof QueryException && $throwable->getPrevious() instanceof Throwable
            ? $throwable->getPrevious()->getMessage()
            : $throwable->getMessage();
    }
}
