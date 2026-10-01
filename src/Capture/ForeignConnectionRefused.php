<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use RuntimeException;

/**
 * A migration method, run by a capture, sent a query to a connection other than the one the capture
 * owns. The query did not run: see {@see CaptureConnectionFence}.
 */
final class ForeignConnectionRefused extends RuntimeException
{
    public static function reaching(string $reached, string $owner): self
    {
        return new self(sprintf(
            'the migration sent a query to the connection "%s", which this capture does not own, so it was refused before it ran; the capture runs a migration on "%s" only',
            $reached,
            $owner,
        ));
    }
}
