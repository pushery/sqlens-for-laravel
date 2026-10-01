<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use RuntimeException;
use Throwable;

/**
 * A shadow run stopped with an error, and `capture.shadow.keep_on_failure` kept its databases.
 *
 * The error that stopped the run names no database, and that is the one thing a person who asked
 * for the database to be kept needs to know. So the error is carried as the previous exception and
 * its message is repeated here, beside the names of the databases still on the server.
 */
final class ShadowDatabaseKept extends RuntimeException
{
    /**
     * @param  list<string>  $databases
     */
    private function __construct(public readonly array $databases, Throwable $stopped)
    {
        $one = count($databases) === 1;

        parent::__construct(sprintf(
            '%s — capture.shadow.keep_on_failure kept %s for inspection: %s. Drop %s when done.',
            $stopped->getMessage(),
            $one ? 'the throwaway database' : 'the throwaway databases',
            implode(', ', $databases),
            $one ? 'it' : 'them',
        ), previous: $stopped);
    }

    /**
     * @param  list<string>  $databases
     */
    public static function after(Throwable $stopped, array $databases): self
    {
        return new self($databases, $stopped);
    }
}
