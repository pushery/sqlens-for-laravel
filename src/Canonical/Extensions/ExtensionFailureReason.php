<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical\Extensions;

/**
 * Why a connection could not be resolved to a usable driver canonicalization — a
 * named reason, so the caller turns it into an undetermined result instead of
 * guessing. The first four values share their backing with DriverResolutionReason
 * on purpose, so a driver-resolution failure maps straight through; the last two
 * are specific to the canonicalization extension point.
 */
enum ExtensionFailureReason: string
{
    /** The driver is a reserved non-goal engine. */
    case ReservedDriver = 'reserved_driver';

    /** The driver key is neither built-in nor registered. */
    case UnknownDriver = 'unknown_driver';

    /** No connection is configured under that name. */
    case ConnectionNotFound = 'connection_not_found';

    /** The connection exists but declares no driver key. */
    case MissingDriverKey = 'missing_driver_key';

    /** The driver resolved, but no canonicalization is registered for it. */
    case MissingCanonicalization = 'missing_canonicalization';

    /** The canonicalization leaves a required capability empty (the missing-artifact case). */
    case IncompleteCapability = 'incomplete_capability';
}
