<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Catalog\SessionBudget;

/**
 * How one engine is told to bound and seal a reader session.
 *
 * The two engines do NOT agree here, and the split is measured rather than assumed. On MySQL a
 * session-wide `transaction_read_only` blocks writes and DDL outright; on PostgreSQL the shape that
 * reliably refused a write through Laravel's connection API was an explicit transaction marked
 * `READ ONLY`. MySQL additionally refuses `SET TRANSACTION` *inside* an open transaction, so its
 * seal has to be issued before the transaction starts. Three differences, one interface, no
 * pretending they are the same.
 */
interface SessionDefense
{
    /**
     * Bounds and identity, applied once when the session opens: the timeouts, and the name the
     * server's activity view shows.
     *
     * ## These statements are for a session THIS PACKAGE OPENED, and that is load-bearing
     *
     * A reader session is SQLens's own: it is opened, used and closed here, so nothing written on
     * it has to be given back and every bound is free to set. Two of the PostgreSQL statements are
     * only safe under that assumption — `idle_in_transaction_session_timeout`, which terminates a
     * session idling inside a transaction, and `application_name`, which overwrites the label a DBA
     * reads sessions by.
     *
     * `Capture\SessionGuard` bounds a BORROWED connection — the host application's — and
     * deliberately sets neither, because on a borrowed connection the first one
     * destroys a transaction the host already had open (measured on PostgreSQL 18.4) and the second
     * hides the host's own identity. That is not a weaker copy of this interface; it is the same
     * promise made to a connection with a different owner.
     *
     * So a statement added here is NOT automatically one to add there. The parity guard in
     * `tests/Unit/Capture/SessionStatementParityTest.php` will say so.
     *
     * @return list<string>
     */
    public function sessionStatements(SessionBudget $budget): array;

    /**
     * What must be issued BEFORE the read transaction opens — MySQL's seal, which the server
     * refuses once a transaction is in progress.
     *
     * @return list<string>
     */
    public function preTransactionStatements(): array;

    /**
     * What must be issued INSIDE the read transaction — PostgreSQL's seal, and the `SET LOCAL`
     * bounds that survive a transaction pooler.
     *
     * @return list<string>
     */
    public function inTransactionStatements(SessionBudget $budget): array;

    /** A write that MUST be refused. The probe that turns the read-only claim into evidence. */
    public function writeProbe(): string;

    /** Whether this SQLSTATE is the engine refusing a write because the session is read-only. */
    public function isReadOnlyRefusal(string $sqlState): bool;

    /**
     * Whether this SQLSTATE means a privilege refused the probe, rather than the session's seal.
     *
     * A separate question on purpose, and not a proof on its own. The probe needs one privilege,
     * the right to create a temporary table, and an engine that asks the grant before the
     * transaction's access mode refuses an account without that right the same way whether or not
     * the account may write elsewhere and whether or not the seal took. Measured on MySQL 8.4: an
     * account holding `INSERT`, `UPDATE` and `DELETE` and no temporary-table right is refused with
     * `42000`, exactly like one holding `SELECT` alone. What such a refusal leaves open is answered
     * by {@see self::grantsForbidWriting()} and {@see self::readOnlyFlagQuery()}.
     *
     * Without this the least-privileged account the documentation recommends cannot be audited at
     * all: its probe write is denied by privilege, the seal reads that as "refused for the wrong
     * reason", and the entire reading fails. Measured on MySQL 8.4 with `GRANT SELECT ON db.*`.
     */
    public function isPrivilegeRefusal(string $sqlState): bool;

    /**
     * A query whose one row answers, in its first column, whether the transaction is read-only.
     *
     * Read after a privilege refused the probe, because the refusal then says nothing about the
     * seal: the flag is asked for instead of inferred.
     */
    public function readOnlyFlagQuery(): string;

    /** Whether the value {@see self::readOnlyFlagQuery()} answered, as text, means read-only. */
    public function flagMeansReadOnly(string $value): bool;

    /**
     * A query listing the connecting account's own grants, one line per row in the first column,
     * or null where no listing this package reads can show that an account cannot write.
     */
    public function grantListingQuery(): ?string;

    /**
     * Whether these grant lines show that the account cannot write: every privilege they name only
     * reads, and none of them could widen that. A role membership, a grant option or a line that
     * does not parse is not read as proof, and neither is an empty listing.
     *
     * @param  list<string>  $lines
     */
    public function grantsForbidWriting(array $lines): bool;

    /**
     * Whether this failure is the session's own time budget firing.
     *
     * A SQLSTATE alone cannot answer this, on either engine.
     *
     * Measured against PostgreSQL 18.0 and MySQL 8.4.10 by provoking each bound:
     *
     *     pg statement_timeout        57014
     *     pg lock_timeout             55P03
     *     mysql max_execution_time    HY000 / 3024
     *     mysql innodb_lock_wait      HY000 / 1205
     *
     * On MySQL the SQLSTATE carries no information at all: `HY000` is the general class, worn
     * equally by a gone server (2006), a lost connection (2013) and a full disk (1030). Reading it
     * as "the server was not at fault" would turn every one of those into a budget the reader is
     * told to relax. So the driver's own error number travels with it.
     *
     * The classification itself lives in {@see SessionTimeoutDetector}, which the shadow path uses
     * too — one answer, reached from both sides.
     *
     * @param  int|null  $driverCode  the driver's own error number, when the exception carried one
     */
    public function isTimeout(string $sqlState, ?int $driverCode): bool;
}
