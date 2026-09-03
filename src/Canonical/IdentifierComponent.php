<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

/**
 * One dot-separated part of an identifier reference — a schema or a name — held in
 * both its original spelling (exactly as written in the source SQL, quotes and
 * all) and its canonical spelling (quoting collapsed, case folded per the driver).
 *
 * `wasQuoted` records whether the source spelled the part with the driver's
 * identifier quote. A folding driver must preserve that distinction: PostgreSQL
 * `"Users"` is a deliberate mixed-case object and is NOT the same as unquoted
 * `Users` (which folds to `users`), so the two never share a canonical form.
 */
final readonly class IdentifierComponent
{
    public function __construct(
        public string $original,
        public string $canonical,
        public bool $wasQuoted,
    ) {}
}
