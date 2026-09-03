<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers;

use Pushery\SQLens\Contracts\Driver;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Rules\ServerVersion as ParsedVersion;

/**
 * Decides whether the server behind a connection is new enough for the driver's
 * rules to mean anything.
 *
 * A supported engine on a too-old server is a DIFFERENT case from an unknown
 * driver, and it gets its own reason and its own sentence. Folding the two
 * together would swallow the cause: one says "upgrade the server", the other says
 * "this engine is out of scope", and those are different actions.
 *
 * The version string is HANDED IN and never fetched here — see {@see self::check()} for why
 * that is a structural guarantee rather than a style. "There is no version at all" belongs to
 * the caller: both suites already name that case, and this unit answering it too would be the
 * same gap reported twice under a second name.
 */
final readonly class ServerVersionFloor
{
    /**
     * The MySQL-compatibility handshake prefix MariaDB sends. No MySQL server ever
     * shipped as 5.5.5, so a banner starting with it is not describing the engine
     * the driver key claims.
     */
    private const string MARIADB_HANDSHAKE_PREFIX = '5.5.5-';

    /**
     * The vendor marker MariaDB puts in its own banner.
     *
     * Needed BESIDE the handshake prefix because the audit reads `version()`, which never
     * carries that prefix. MariaDB reports e.g. `11.4.4-MariaDB`, whose leading numeric run
     * parses cleanly and clears every floor — while `5.5.68-MariaDB` parses to 5.5.68 and
     * would be reported as a MySQL below 8.4, telling a MariaDB operator to upgrade a MySQL
     * they do not run. Confident, specific, and about the wrong product.
     *
     * Kept HERE rather than borrowed from {@see EngineIdentity}, even though that unit ships
     * the same predicate. The two answer different questions about the same string: that one
     * decides WHICH engine is speaking and refuses the run; this one only refuses to judge a
     * version it cannot attribute, and it has to keep doing so even where the identity check
     * does not run — the `--file` fast path, and any caller that has a pin but no server.
     */
    private const string MARIADB_VENDOR_MARKER = 'mariadb';

    /**
     * The failure to report, or null when the version meets the driver's floor.
     *
     * The version string is REQUIRED, and it is never acquired here. It used to default to
     * `$this->versions->resolve($connection)`, and that default was a trap rather than a
     * convenience: Laravel connects lazily, so on a cold run the acquisition unit hands back
     * null and this unit answered `unknownServerVersion` — a failure reported to every healthy
     * user, produced by the one check that exists to stop users being misadvised. Requiring
     * the value makes that mistake unmakeable rather than merely undone.
     *
     * The CALLER decides which string: a raw server banner, or an `assume_server_version` pin.
     * A pinned version takes the same path as a detected one, or the pin would prove something
     * the real run does not. The caller also owns the "there is no version at all" case — both
     * suites already report that under their own named reason, and a second notice about it
     * from here would be the same fact said twice.
     */
    public function check(Driver $driver, string $banner): ?DriverResolutionFailure
    {
        // A banner this unit cannot attribute to the driver's own engine is NOT
        // judged against the floor. Parsing a MariaDB handshake yields 5.5.5, which
        // is below every floor SQLens has — reporting that as "upgrade your MySQL"
        // would be confident, wrong advice about a server that is not MySQL at all.
        // Deciding WHICH engine it actually is belongs to the engine-identity check;
        // this unit only refuses to pretend it knows.
        if (str_starts_with($banner, self::MARIADB_HANDSHAKE_PREFIX)
            || str_contains(strtolower($banner), self::MARIADB_VENDOR_MARKER)) {
            return DriverResolutionFailure::unknownServerVersion(
                $driver->key(),
                'the banner names another engine, so it does not describe the engine the driver claims',
            );
        }

        $detected = ParsedVersion::parse($banner, $driver->key());

        if ($detected instanceof UndeterminedReason) {
            return DriverResolutionFailure::unknownServerVersion(
                $driver->key(),
                sprintf('the reported banner "%s" carries no readable version', $banner),
            );
        }

        $required = ParsedVersion::parse($driver->minimumServerVersion(), $driver->key());

        // The driver's own floor is package data, not user input; an unreadable one
        // is a packaging bug and must not be mistaken for a too-old server.
        if ($required instanceof UndeterminedReason) {
            return DriverResolutionFailure::unknownServerVersion(
                $driver->key(),
                sprintf('the driver declares an unreadable minimum version "%s"', $driver->minimumServerVersion()),
            );
        }

        return $detected->isBelow($required)
            ? DriverResolutionFailure::versionBelowFloor($driver->key(), $banner, $driver->minimumServerVersion())
            : null;
    }
}
