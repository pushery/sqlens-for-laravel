<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Checks;

use RuntimeException;

/**
 * The server answered, but not with the state a check needed.
 *
 * Its own type so a check can tell "the read failed" from "the read succeeded and said nothing" —
 * they arrive at the same catch and mean different things, and only one of them is worth putting in
 * a message a person reads.
 */
final class PreflightStateUnreadable extends RuntimeException {}
