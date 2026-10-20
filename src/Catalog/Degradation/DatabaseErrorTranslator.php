<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Degradation;

use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Catalog\SkipReason;
use Pushery\SQLens\Findings\CompositeCredentialRedactor;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Throwable;

/**
 * Turns a database error into a named skip — never a stack trace, never a silent pass.
 *
 * On a managed database half the catalog is unreadable without a superuser, and that is the ordinary
 * case rather than a fault: RDS, Aurora, Cloud SQL and Neon all withhold something. A reader that
 * threw would be unusable there, and one that swallowed the error would report a clean audit of a
 * database it could not see. Both engines answer in SQLSTATE, so the SQLSTATE is what decides.
 *
 * ## The codes, and what each becomes
 *
 * | SQLSTATE | PostgreSQL 18 | MySQL 8.4 | becomes |
 * |---|---|---|---|
 * | `42501` | `permission denied for view pg_hba_file_rules` | — | insufficient_privilege |
 * | `42000` | — | `SELECT command denied … for table 'setup_instruments'` (1142) | insufficient_privilege |
 * | `42P01` | `relation "pg_catalog.x" does not exist` | — | not_readable |
 * | `42S02` | — | `Unknown table 'X' in information_schema` | not_readable |
 * | `42704` | an undefined object, such as an unknown role | — | not_readable |
 *
 * The messages were measured on real servers, except the last row's, which follows the name
 * PostgreSQL gives the class.
 *
 * MySQL's `42000` is "syntax error or access violation", one class for both, so the driver's
 * error number decides. A statement the server cannot parse (1064), an unknown database (1049)
 * and an unknown function (1305) arrive under it as well, and only the numbers of a privilege
 * refusal make it a denial; any other number keeps its code as `unexpected_error`. A `42000` that
 * carries no number is still read as a denial, the class's ordinary case on a catalog read.
 *
 * Anything else keeps its code and becomes `unexpected_error`. That is not a catch-all shrug: the
 * code is REQUIRED on that reason precisely so a case nobody anticipated arrives with the one piece
 * of evidence needed to anticipate it next time.
 *
 * ## What it deliberately does not translate
 *
 * A timeout the reader set on itself. `ReaderSession::isOwnTimeout()` owns that distinction, and
 * filing the tool's own self-restraint as a database fault would blame the database for a bound this
 * package chose.
 */
final readonly class DatabaseErrorTranslator
{
    /** SQLSTATEs that mean "the role may not read this". */
    private const array DENIED = ['42501', '42000'];

    /**
     * MySQL's error numbers for a refused privilege, the part of `42000` that is a denial.
     *
     * 1044 a database, 1142 a table, 1143 a column, 1227 a privilege the statement needs, 1370 a
     * routine.
     */
    private const array MYSQL_DENIALS = [1044, 1142, 1143, 1227, 1370];

    /** SQLSTATEs that mean "there is nothing there to read". */
    private const array ABSENT = ['42P01', '42S02', '42704'];

    /**
     * Run one part of a reading, and turn a failure into a named skip instead of ending the run.
     *
     * Both readers do exactly this around every query battery, and having it once rather than twice
     * is the point: a second copy is where the two engines' error handling would start to differ for
     * no reason anyone chose. One battery failing must not end the reading — on a managed database
     * that is the difference between a partial answer and no answer at all.
     *
     * @template T
     *
     * @param  callable(): list<T>  $read
     * @param  list<CatalogSkip>  $skips
     * @return list<T>
     */
    public static function attempt(callable $read, SchemaObjectType $type, string $reference, array &$skips): array
    {
        try {
            return $read();
        } catch (Throwable $error) {
            $skips[] = self::skipFor($type, $reference, $error);

            return [];
        }
    }

    /**
     * The same, for a reading that runs under a bound this package set on itself.
     *
     * The distinction {@see ReaderSession::isOwnTimeout()} owns, applied where it is easiest to
     * lose. `attempt()` turns every failure into a database-shaped skip, which is right for every
     * failure the database caused — and wrong for the one it did not. A statement killed by the
     * timeout the reader installed a moment earlier is not a fault of the server; it is this package
     * reaching the limit it chose, and filing it as `unexpected_error` would send somebody looking
     * for a problem on an instance that has none.
     *
     * It matters most for the deploy readers, because they are the ones that run under a deliberately
     * short budget. On them a timeout is not an exceptional event at all — it is the expected way a
     * reading ends on a large schema, and the report has to say "the gate ran out of its own time"
     * rather than "the database failed".
     *
     * @template T
     *
     * @param  callable(): list<T>  $read
     * @param  list<CatalogSkip>  $skips
     * @return list<T>
     */
    public static function attemptBounded(
        callable $read,
        SchemaObjectType $type,
        string $reference,
        ReaderSession $session,
        array &$skips,
    ): array {
        try {
            return $read();
        } catch (Throwable $error) {
            $skips[] = $session->isOwnTimeout($error)
                ? CatalogSkip::for(
                    $type,
                    $reference,
                    SkipReason::BudgetExceeded,
                    sprintf(
                        'reading %s reached the time budget this run set for itself (%d ms) — the '
                        .'server was not at fault, and the objects already read are still reported',
                        $reference,
                        $session->readBudgetMs(),
                    ),
                )
                : self::skipFor($type, $reference, $error);

            return [];
        }
    }

    /**
     * The skip this error becomes.
     *
     * The reference is the AREA or object the read was about, not the SQL: a reader told that
     * "a query failed" has to go find which one, and by then the run is over.
     */
    public static function skipFor(SchemaObjectType $type, string $reference, Throwable $error): CatalogSkip
    {
        $state = ReaderSession::sqlStateOf($error);

        if ($state !== null && in_array($state, self::DENIED, true) && ! self::isAnotherKindOf42000($state, $error)) {
            return CatalogSkip::for(
                $type,
                $reference,
                SkipReason::InsufficientPrivilege,
                sprintf('the reading role may not read %s (SQLSTATE %s)', $reference, $state),
            );
        }

        if ($state !== null && in_array($state, self::ABSENT, true)) {
            return CatalogSkip::for(
                $type,
                $reference,
                SkipReason::NotReadable,
                sprintf('%s does not exist on this server (SQLSTATE %s)', $reference, $state),
            );
        }

        // No SQLSTATE at all is still an unexpected_error rather than a softer reason, and the
        // placeholder is honest about what is missing: that reason REQUIRES a code, and inventing a
        // plausible one would be worse than admitting the error carried none.
        //
        // The driver's own words, through the redactor. This is the one path in the package where a
        // raw error message becomes user-visible finding text verbatim, which makes it the one path
        // where an unredacted message reaches a report, a CI log and anywhere that log is pasted.
        // Laravel appends the connection's host, port and database to every query exception, so the
        // message arrives carrying them even when the driver's own half is harmless.
        return CatalogSkip::unexpectedError(
            $type,
            $reference,
            $state ?? '(no SQLSTATE)',
            sprintf('reading %s failed: %s', $reference, new CompositeCredentialRedactor()->redact($error->getMessage())),
        );
    }

    /** Whether a `42000` carries a driver number that is not one of MySQL's privilege refusals. */
    private static function isAnotherKindOf42000(string $state, Throwable $error): bool
    {
        $code = ReaderSession::driverCodeOf($error);

        return $state === '42000' && $code !== null && ! in_array($code, self::MYSQL_DENIALS, true);
    }
}
