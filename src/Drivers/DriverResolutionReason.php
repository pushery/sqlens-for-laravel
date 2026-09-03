<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers;

/**
 * Why a connection could not be resolved to a supported driver — a named reason,
 * so the engine turns it into an undetermined result instead of guessing or
 * silently falling back to another driver. Every resolution failure is one of
 * these.
 */
enum DriverResolutionReason: string
{
    /** The driver is a reserved non-goal engine (mariadb/sqlite/sqlsrv). */
    case ReservedDriver = 'reserved_driver';

    /** The driver key is neither built-in nor registered. */
    case UnknownDriver = 'unknown_driver';

    /** The connection exists but declares no driver key. */
    case MissingDriverKey = 'missing_driver_key';

    /** No connection is configured under that name. */
    case ConnectionNotFound = 'connection_not_found';

    /** The engine is supported, but this server runs a version below the floor. */
    case VersionBelowFloor = 'version_below_floor';

    /** The server did not report a version this build can attribute to the driver. */
    case UnknownServerVersion = 'unknown_server_version';

    /** The connection uses Laravel's mysql driver, but the server is a MariaDB. */
    case MariaDbBehindMysqlDriver = 'mariadb_behind_mysql_driver';

    /** No connection was open, so the engine behind the driver key is unverified. */
    case UnverifiedEngineIdentity = 'unverified_engine_identity';
}
