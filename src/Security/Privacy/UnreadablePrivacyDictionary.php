<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Privacy;

use RuntimeException;

/**
 * The bundled or configured privacy dictionary could not be turned into terms.
 *
 * It throws rather than degrading to an empty list, and that is the three-valued rule applied to a
 * data file: a dictionary that silently became empty would make every privacy rule report nothing,
 * which reads exactly like a clean database. A named failure is the only answer that cannot be
 * mistaken for good news.
 */
final class UnreadablePrivacyDictionary extends RuntimeException
{
    public function __construct(public readonly string $path, string $why)
    {
        parent::__construct(sprintf('The privacy dictionary at %s could not be read: %s.', $path, $why));
    }
}
