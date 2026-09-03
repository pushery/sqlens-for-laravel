<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use LogicException;

/**
 * A driver was registered in a way that is a programming error: a key already
 * taken, or a reserved key that would smuggle a non-goal engine past the
 * unsupported path. Both fail loud — a silently overwritten driver, or a MariaDB
 * quietly served MySQL-alien rules, is exactly the bug nobody notices.
 */
final class InvalidDriverRegistration extends LogicException
{
    public static function duplicateKey(string $key): self
    {
        return new self(sprintf(
            'Driver key "%s" is already registered; registering it again would silently overwrite a driver.',
            $key,
        ));
    }

    public static function reservedKey(string $key): self
    {
        return new self(sprintf(
            'Driver key "%s" is reserved and cannot be registered: it is a non-goal engine that must fall through to the unsupported path.',
            $key,
        ));
    }
}
