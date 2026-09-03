<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use InvalidArgumentException;

/**
 * A project override named an operation class this build does not have.
 *
 * Thrown rather than ignored, and the reason is the shape of the harm: an ignored override is
 * silent. The value has no effect, the shipped default stays in force, and the project believes it
 * configured something. A typo then costs exactly as much as never having written the line, except
 * that somebody thinks the line is there.
 */
final class UnknownEscalationOperation extends InvalidArgumentException
{
    /** @param list<string> $known */
    public function __construct(string $operation, array $known)
    {
        sort($known);

        parent::__construct(sprintf(
            'the escalation threshold override names "%s", which is not an operation class this '
            .'build knows. Known classes: %s. Nothing was applied — an override that is silently '
            .'ignored is worse than one that is refused, because the project believes it took '
            .'effect.',
            $operation,
            implode(', ', $known),
        ));
    }
}
