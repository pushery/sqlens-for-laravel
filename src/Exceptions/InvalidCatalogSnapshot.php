<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use LogicException;

/**
 * A catalog snapshot, or the context it must carry, was built without something the model requires.
 *
 * A wiring error rather than a user error, so it throws: an `undetermined` says "we looked and could
 * not tell", and here nothing was assembled to look with. A snapshot that cannot name its driver or
 * its server version is one no version-windowed rule can resolve against and no drift comparison can
 * interpret — and both of those failures are silent, which is why this one is not.
 */
final class InvalidCatalogSnapshot extends LogicException {}
