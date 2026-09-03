<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use LogicException;

/**
 * A catalog skip was built without what its reason requires.
 *
 * A wiring error, not a user error, so it throws rather than becoming an `undetermined`: an
 * undetermined says "we looked and could not tell", and here the reader HAS the answer and simply
 * did not pass it. Accepting the skip anyway would put a fault on record with nothing to look up,
 * which reads like diligence and is the same dead end as no record at all.
 */
final class InvalidCatalogSkip extends LogicException {}
