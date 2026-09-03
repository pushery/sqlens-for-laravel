<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use LogicException;
use Pushery\SQLens\Catalog\SkipReason;

/**
 * A partial reading was built without naming a single withheld field.
 *
 * A wiring error, not a user error, so it throws rather than degrading to an `undetermined`: an
 * undetermined says "we looked and could not tell", and here the reader KNOWS which field it did not
 * get and simply did not say. A partial reading that names nothing is indistinguishable from a
 * complete one at every point downstream — the exact silent green the readability field exists to
 * prevent, arriving through the field itself.
 */
final class InvalidReadability extends LogicException
{
    public static function partialWithoutFields(SkipReason $reason): self
    {
        return new self(sprintf(
            'A partial reading must name at least one withheld field; got reason "%s" with none. '
            .'Use Readability::unreadable() when nothing beyond the identity could be read.',
            $reason->value,
        ));
    }
}
