<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use RuntimeException;

/**
 * The debt ledger could not be written, and the file at its path is the one that was there before.
 *
 * Thrown rather than returned: a recording run that carried on would report the debts it recorded
 * while the file still held the old account, and the next run would read that account as current.
 */
final class UnwritableDebtLedger extends RuntimeException
{
    public static function at(string $path): self
    {
        return new self(sprintf(
            'The debt ledger at "%s" could not be written, and the file there, if any, is unchanged. Check that its directory is writable for the user running artisan.',
            $path,
        ));
    }
}
