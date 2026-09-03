<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

use PDOException;
use Throwable;

/**
 * Recognizes the exceptions a shadow session's OWN timeouts raise, so a bounded
 * session that fires is reported as `undetermined` (`shadow_session_timeout`) rather
 * than passed through as a failure or a raw exception.
 *
 * "Primum non nocere" bounds every shadow session (statement, lock, and idle-in-
 * transaction budgets). When one of those budgets fires, the run did not fail
 * because the migration is wrong — it fired because the tool refused to sit on the
 * source instance. That is an honest "could not determine", not a fault in the
 * migration, so it must not become a `CAP.L0.MIGRATE_ERROR`.
 *
 * The signatures are engine-specific and matched narrowly:
 *   - PostgreSQL raises a distinct SQLSTATE per budget — `57014` (statement_timeout),
 *     `55P03` (lock_timeout), `25P03` (idle_in_transaction_session_timeout).
 *   - MySQL uses the general `HY000` SQLSTATE, so the driver error number is what
 *     distinguishes a timeout — `1205` (innodb_lock_wait_timeout) and `3024`
 *     (max_execution_time).
 *
 * The pure {@see self::matchesTimeout()} decides from those two facts, kept apart
 * from the throwable so both engines' cases are testable without provoking a real
 * timeout on each.
 */
final class SessionTimeoutDetector
{
    /** PostgreSQL SQLSTATEs for the statement, lock, and idle-transaction budgets. */
    private const array TIMEOUT_SQLSTATES = ['57014', '55P03', '25P03'];

    /** MySQL driver error numbers for a lock-wait and a statement-execution timeout. */
    private const array TIMEOUT_DRIVER_CODES = [1205, 3024];

    public static function isSessionTimeout(Throwable $throwable): bool
    {
        return self::matchesTimeout((string) $throwable->getCode(), self::driverCode($throwable));
    }

    /**
     * Whether a SQLSTATE and (optional) driver error number identify a session
     * timeout. Pure, so the PostgreSQL and MySQL signatures are both testable
     * directly.
     */
    public static function matchesTimeout(string $sqlState, ?int $driverCode): bool
    {
        return in_array($sqlState, self::TIMEOUT_SQLSTATES, true)
            || ($driverCode !== null && in_array($driverCode, self::TIMEOUT_DRIVER_CODES, true));
    }

    /** The driver-specific error number a query exception carries, if any. */
    private static function driverCode(Throwable $throwable): ?int
    {
        $previous = $throwable->getPrevious();

        if ($previous instanceof PDOException && isset($previous->errorInfo[1]) && is_int($previous->errorInfo[1])) {
            return $previous->errorInfo[1];
        }

        return null;
    }
}
