<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

/**
 * The refusal that ended a reader session's reading, shared with every session derived from it.
 *
 * A session narrowed with {@see ReaderSession::withBudget()} is a new object on the same connection.
 * A refusal kept on the object it happened to would let the narrowed one probe again, and every probe
 * on a session whose seal did not take is a write the server accepts.
 */
final class ReaderSessionRefusal
{
    public ?UnsealedReaderSession $refusal = null;
}
