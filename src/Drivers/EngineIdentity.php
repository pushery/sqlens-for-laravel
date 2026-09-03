<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers;

use Pushery\SQLens\Contracts\Driver;

/**
 * Confirms that the engine actually answering is the engine the driver key names.
 *
 * The case this exists for is MariaDB behind Laravel's `mysql` driver. Laravel
 * connects to it happily, the config says `mysql`, and every SQLens rule would
 * then reason about MySQL 8.4 semantics that MariaDB does not share — advice that
 * is confident, specific, and wrong. The configured driver name is a claim, not a
 * verification.
 *
 * The banner is the only evidence, and it comes from the ONE acquisition unit. It
 * has to be the handshake value: only that carries MariaDB's `5.5.5-`
 * compatibility prefix, and a `select version()` would both miss it and be an
 * intervention this package does not make.
 *
 * When no connection is open there is no evidence, and that is REPORTED. Reading
 * "the config says mysql" as proof would be exactly the guessing heuristic the
 * driver layer refuses.
 */
final readonly class EngineIdentity
{
    /**
     * MariaDB's MySQL-compatibility handshake prefix. No MySQL server ever shipped
     * as 5.5.5, so the prefix is unambiguous rather than a heuristic.
     */
    private const string HANDSHAKE_PREFIX = '5.5.5-';

    /** The vendor marker MariaDB puts in its own banner, in either form. */
    private const string VENDOR_MARKER = 'mariadb';

    /**
     * Whether a banner describes a MariaDB server. Its own function, tested against
     * both documented shapes, rather than a regex buried in a resolution branch.
     */
    public static function isMariaDb(string $banner): bool
    {
        return str_starts_with($banner, self::HANDSHAKE_PREFIX)
            || str_contains(strtolower($banner), self::VENDOR_MARKER);
    }

    /**
     * The failure to report, or null when the engine matches the driver.
     *
     * `$banner` is REQUIRED and nullable, and both halves are deliberate. REQUIRED, because a
     * default would let a caller omit the evidence and have this unit fetch it from a
     * connection the caller never named — the trap the sibling floor unit was rebuilt to make
     * unmakeable. NULLABLE, because "there was no banner" is a real and reportable answer here
     * rather than a missing argument: it is the unverified-identity arm, and a caller who has
     * no evidence has to say so out loud instead of skipping the question.
     *
     * Only the mysql driver can be fooled this way: a `mariadb` driver key is
     * already refused by the registry without touching a server, and PostgreSQL has
     * no engine wearing its banner.
     */
    public function check(Driver $driver, ?string $banner): ?DriverResolutionFailure
    {
        if ($driver->key() !== 'mysql') {
            return null;
        }

        if ($banner === null) {
            return DriverResolutionFailure::unverifiedEngineIdentity($driver->key());
        }

        return self::isMariaDb($banner)
            ? DriverResolutionFailure::mariaDbBehindMysqlDriver($banner)
            : null;
    }
}
