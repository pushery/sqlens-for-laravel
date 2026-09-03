<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use InvalidArgumentException;

/**
 * A check result that could not be built, because building it would have produced a silent green.
 *
 * Thrown rather than degraded on purpose. This is a bug in a check inside this package, not a fact
 * about somebody's database — and a package that quietly repaired its own malformed results would
 * be doing exactly what it forbids everywhere else.
 */
final class InvalidCheckResult extends InvalidArgumentException {}
