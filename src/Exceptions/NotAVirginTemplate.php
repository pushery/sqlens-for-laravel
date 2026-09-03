<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use RuntimeException;

/**
 * A database offered as a shadow clone template turned out to hold rows.
 *
 * It is thrown, not returned as a three-valued result, and that is deliberate.
 * Everywhere else this package answers "could not check" with an `undetermined` and
 * carries on; here carrying on would mean cloning whatever data the database holds
 * into a throwaway. A shadow run is an optional truth mode — losing it costs a user
 * nothing next to copying a production dataset — so the only safe answer is to stop.
 */
final class NotAVirginTemplate extends RuntimeException
{
    private function __construct(string $message, public readonly string $database, public readonly int $rowsFound)
    {
        parent::__construct($message);
    }

    public static function holdingRows(string $database, int $rowsFound): self
    {
        return new self(
            sprintf(
                'The database "%s" was offered as a shadow clone template but holds %d row(s). Cloning it would copy that data into the shadow database, so the run was stopped.',
                $database,
                $rowsFound,
            ),
            $database,
            $rowsFound,
        );
    }
}
