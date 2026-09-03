<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use RuntimeException;

/**
 * A connection reached the catalog layer with a driver nothing registered readers for.
 *
 * Always a wiring bug in this package rather than a user's misconfiguration: an unsupported engine
 * is refused much earlier, by the instance resolver, with a named message. Reaching here means a
 * driver was accepted as supported and then had no readers — so the message names both what was
 * asked for and what is registered, because that pair is the whole diagnosis.
 */
final class UnsupportedCatalogDriver extends RuntimeException
{
    /** @param  list<string>  $registered */
    public function __construct(public readonly string $driver, public readonly array $registered)
    {
        parent::__construct(sprintf(
            'No catalog readers are registered for the "%s" driver; registered: %s.',
            $driver,
            $registered === [] ? 'none' : implode(', ', $registered),
        ));
    }
}
