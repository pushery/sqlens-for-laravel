<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use RuntimeException;
use Throwable;

/**
 * The reader session could not prove it is read-only.
 *
 * It throws rather than degrading to a partial snapshot, and that is a deliberate asymmetry with
 * the rest of this layer: an unreadable OBJECT is a named skip, because reading less than
 * everything is a normal outcome. An unsealed SESSION is not a partial reading — it is a tool that
 * has lost the one guarantee it offers about itself, and continuing would mean auditing a
 * production database from a connection that can write to it.
 */
final class UnsealedReaderSession extends RuntimeException
{
    /** The write probe went through. The session is not read-only, whatever the settings report. */
    public static function acceptedAWrite(): self
    {
        return new self(
            'The catalog reader session accepted a write. Its read-only seal did not take, so the read was '
            .'abandoned: SQLens will not audit a database from a session it cannot prove is read-only. This is '
            .'the tool refusing to trust its own configuration rather than yours.',
        );
    }

    /**
     * A privilege refused the probe, and nothing else proves the seal: the account's grants do not
     * show that it cannot write, and the transaction's read-only flag is off.
     */
    public static function refusedByPrivilegeAlone(string $sqlState, Throwable $previous): self
    {
        return new self(sprintf(
            'The catalog reader session\'s write probe was refused with SQLSTATE %s, which says the account '
            .'lacks the one privilege the probe needs, not that it cannot write. Its grants do not show that it '
            .'cannot, and the transaction\'s read-only flag is off, so the seal did not take and the read was '
            .'abandoned: SQLens will not audit a database from a session it cannot prove is read-only.',
            $sqlState,
        ), previous: $previous);
    }

    /** The probe failed for some other reason, which proves nothing about the seal. */
    public static function refusedForTheWrongReason(string $sqlState, Throwable $previous): self
    {
        return new self(sprintf(
            'The catalog reader session refused its own write probe with SQLSTATE %s, which is not the '
            .'read-only refusal the seal was supposed to produce. The probe therefore proves nothing, and a '
            .'seal that cannot be proven is not relied on.',
            $sqlState,
        ), previous: $previous);
    }
}
