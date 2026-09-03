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
     * Whether this SQLSTATE means the account is not ALLOWED to write, rather than the session
     * being sealed against it.
     *
     * A separate question on purpose. Both answers prove the probe's point — nothing this session
     * does can write — and an account refused for lack of privilege proves it more durably than a
     * session flag, which a later statement could clear. But they prove DIFFERENT things: one is
     * about the session, the other about the grant, and a reader that folded them together could
     * no longer say which guarantee it is standing on.
     *
     * Without this the least-privileged account the documentation recommends cannot be audited at
     * all: its probe write is denied by privilege, the seal reads that as "refused for the wrong
     * reason", and the entire reading fails. Measured on MySQL 8.4 with `GRANT SELECT ON db.*`.
     */
    public function isPrivilegeRefusal(string $sqlState): bool;

    /** Whether this SQLSTATE is the session's own time budget firing. */
    public function isTimeout(string $sqlState): bool;
}
