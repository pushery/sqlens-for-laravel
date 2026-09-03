<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use InvalidArgumentException;

/**
 * The reader was asked for a connection the application does not define.
 *
 * Named rather than silently skipped: a run that audits nothing because it was pointed at a typo
 * reads exactly like a run that audited everything and found nothing wrong.
 */
final class UnknownReaderConnection extends InvalidArgumentException
{
    public function __construct(string $source)
    {
        parent::__construct(sprintf(
            'No connection named "%s" is configured, so the catalog reader has nothing to read from and '
            .'audited nothing. Fix the name, or add the connection.',
            $source,
        ));
    }
}
