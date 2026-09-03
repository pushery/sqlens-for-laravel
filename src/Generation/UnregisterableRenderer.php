<?php

declare(strict_types=1);

namespace Pushery\SQLens\Generation;

use RuntimeException;

/**
 * A renderer could not be registered, and the message says what it failed to declare.
 *
 * Registration refuses rather than defaults, and the direction is why. A renderer admitted with a
 * guessed family runs under `--target=all` somewhere it was never meant to, writing a file into a
 * repository whose owner then sees their own `--check` go red. Refusing costs one clear error at
 * boot; defaulting costs a file in somebody else's project.
 */
final class UnregisterableRenderer extends RuntimeException
{
    /** @param  list<string>  $known */
    public static function unknownFamily(string $renderer, string $declared, array $known): self
    {
        return new self(sprintf(
            'The renderer %s declares the artifact family "%s", which this build does not know, so its '
            .'output has no destination. Declare one of: %s.',
            $renderer,
            $declared === '' ? '(empty)' : $declared,
            implode(', ', $known),
        ));
    }

    public static function duplicatePath(string $family, string $path, string $first, string $second): self
    {
        return new self(sprintf(
            'Two %s renderers both write %s: %s and %s. One path can only hold one artifact, and '
            .'whichever ran last would silently win.',
            $family,
            $path,
            $first,
            $second,
        ));
    }
}
