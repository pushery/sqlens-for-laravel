<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use RuntimeException;

/**
 * A naming pattern that compiles, and that PCRE gave up matching against one identifier.
 *
 * Not {@see InvalidNamingPattern}, which is about a pattern that cannot work at all and stops the
 * run. This one is about a single name: a pattern that backtracks without bound, or a name that is
 * not valid UTF-8 under a `/u` pattern, makes `preg_match()` answer `false` for that name alone.
 * The naming rules catch it and report the object or statement as undetermined, and every other
 * name in the run is judged as usual.
 */
final class NamingPatternGaveUp extends RuntimeException
{
    /**
     * PCRE's own reason is kept, because "Backtrack limit exhausted" points at the pattern and
     * "Malformed UTF-8 characters" at the name. The name is scrubbed to valid UTF-8, so the message
     * stays printable and encodable when the name itself is the problem.
     */
    public static function on(string $pattern, string $identifier, string $reason): self
    {
        return new self(sprintf(
            'The naming pattern "%s" could not judge the identifier "%s": PCRE gave up with "%s". The pattern '
            .'compiles, so every other name is judged as usual; simplify the pattern if it backtracks, or '
            .'check how the name is encoded.',
            $pattern,
            mb_scrub($identifier, 'UTF-8'),
            $reason,
        ));
    }
}
