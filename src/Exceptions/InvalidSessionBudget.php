<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use InvalidArgumentException;

/**
 * The catalog reader's session budget was configured with a value that would remove the bound.
 *
 * A configuration error rather than a runtime one, so it throws where the config is read instead of
 * degrading into an unbounded reader. The alternative — accepting zero and treating it as "no
 * limit" — would let a project turn off the one guarantee this layer makes, by typing what looks
 * like a sensible default.
 */
final class InvalidSessionBudget extends InvalidArgumentException {}
