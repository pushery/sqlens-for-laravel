<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical\Extensions;

use Pushery\SQLens\Drivers\DriverResolutionFailure;

/**
 * A named failure to resolve a driver canonicalization — the "no silent green" of
 * the extension point. Built only through named factories; a driver-resolution
 * failure maps straight through (shared backing values), and the two
 * canonicalization-specific cases have their own factories.
 */
final readonly class ExtensionFailure
{
    private function __construct(
        public ExtensionFailureReason $reason,
        public string $detail,
    ) {}

    /** Carry a driver-resolution failure through — reserved/unknown driver, missing key, missing connection. */
    public static function fromResolution(DriverResolutionFailure $failure): self
    {
        return new self(
            ExtensionFailureReason::from($failure->reason->value),
            $failure->detail,
        );
    }

    public static function missingCanonicalization(string $driverKey): self
    {
        return new self(
            ExtensionFailureReason::MissingCanonicalization,
            sprintf('driver "%s" resolved but no canonicalization is registered for it', $driverKey),
        );
    }

    public static function incompleteCapability(string $driverKey, string $capability): self
    {
        return new self(
            ExtensionFailureReason::IncompleteCapability,
            sprintf('driver "%s" canonicalization declares no %s', $driverKey, $capability),
        );
    }
}
