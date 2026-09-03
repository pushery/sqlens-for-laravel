<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use RuntimeException;

/**
 * A protocol frame could not be put on the wire whole.
 *
 * Thrown rather than swallowed, and that is the point of it existing. `fwrite()` on a socket may
 * legitimately take fewer bytes than it was given; the transport pushes the remainder until it is
 * gone. A stream that then stops accepting bytes altogether has left the client with a frame that
 * ends mid-token — and a JSON parser that meets one never recovers, because every later frame is
 * read against a position that no longer means anything.
 *
 * So the failure is loud. "The client did not get the answer" is a state somebody can act on;
 * "the client got half an answer and does not know" is not.
 */
final class McpFrameNotDelivered extends RuntimeException
{
    private function __construct(public readonly int $written, public readonly int $total, string $message)
    {
        parent::__construct($message);
    }

    /** The stream stopped taking bytes with part of the frame already out. */
    public static function afterBytes(int $written, int $total): self
    {
        return new self($written, $total, sprintf(
            'The output stream stopped accepting bytes after %d of %d, so this frame reached the '
            .'client incomplete. A partial frame cannot be recovered from — a client parser that '
            .'meets one reads every later frame against a broken position.',
            $written,
            $total,
        ));
    }
}
