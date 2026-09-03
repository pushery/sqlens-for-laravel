<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Canonical\CanonicalizationFailure;
use Pushery\SQLens\Canonical\Identifier;
use Pushery\SQLens\Contracts\DriverCanonicalization;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The database object a debt is about, named the ONE way the ledger records it.
 *
 * ## Why canonicalization is the whole point
 *
 * `"Public"."Orders"`, `public.orders` and `PUBLIC.ORDERS` are one object on PostgreSQL and the
 * ledger has to agree. Without that, a debt recorded by a run that saw one spelling and re-read by a
 * run that saw another is TWO debts: the account grows a duplicate every time the quoting changes,
 * and the number it reports stops meaning anything. That is the drift trap the comparator has to
 * avoid, arriving one layer earlier.
 *
 * The folding rules are the engine's, not this class's — PostgreSQL folds an unquoted identifier
 * down, MySQL does not — so the canonicalization arrives as an argument. A core class that decided
 * which engine folds how would be exactly the driver knowledge the purity census keeps out.
 *
 * ## Why the type is part of the identity
 *
 * A table and an index may carry the same name in different namespaces, and they are not the same
 * debt: dropping an invalid index does not settle a constraint that was never validated. Two debts
 * that shared an id would silently overwrite each other in a ledger keyed by identity.
 */
final readonly class DebtSubject
{
    private function __construct(
        /** The canonical, schema-qualified reference — what the ledger writes and compares. */
        public string $canonical,
        public SchemaObjectType $type,
    ) {}

    /**
     * The subject a reference names, or null when the reference cannot be canonicalized.
     *
     * Null rather than the raw string, deliberately. Recording an un-canonicalized reference is
     * what creates the duplicate this class exists to prevent — and a debt the tool cannot name
     * precisely is one it should not silently commit to a file people review.
     */
    public static function of(string $reference, SchemaObjectType $type, DriverCanonicalization $canonicalization): ?self
    {
        $identifier = Identifier::parse($reference, $canonicalization);

        if ($identifier instanceof CanonicalizationFailure) {
            return null;
        }

        return new self($identifier->canonical(), $type);
    }
}
