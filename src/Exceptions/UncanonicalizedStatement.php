<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use LogicException;

/**
 * A captured statement was handed to the rule engine before the canonicalization
 * layer had run on it.
 *
 * This is a wiring error, not a user error, so it throws rather than becoming an
 * `undetermined` finding: an undetermined says "we looked and could not tell",
 * and here nobody looked — the pipeline was assembled wrong. Silently falling
 * back to the raw grammar text would hand rules exactly the quirks the
 * canonicalization layer exists to remove, and every rule would then be subtly
 * matching on Laravel's formatting instead of on SQL.
 */
final class UncanonicalizedStatement extends LogicException
{
    public static function inMigration(string $migrationClass, int $sequence): self
    {
        return new self(sprintf(
            'Statement %d of migration "%s" reached the rule engine without a canonical form. '
            .'Run the captured statements through the canonicalization layer before building subjects.',
            $sequence,
            $migrationClass,
        ));
    }
}
