<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

use Pushery\SQLens\Exceptions\NotAVirginTemplate;

/**
 * A database that has been VERIFIED to hold no rows, and is therefore safe to clone
 * a shadow database from.
 *
 * This type exists for one reason, and it is the whole safety story of the shadow
 * mode on PostgreSQL. `CREATE DATABASE … TEMPLATE <source>` copies the source byte
 * for byte — every row of it. A provisioner that took its template as a plain string
 * would happily accept the live database and clone the entire production dataset
 * into a throwaway. Nothing about the SQL would look wrong while it happened.
 *
 * So the template is not a string. It is a value with a private constructor, minted
 * by {@see verifiedEmpty()} only after the caller has COUNTED the rows and found
 * none. The emptiness is therefore a checked fact, not a claim a caller makes about
 * a name it happens to hold — and passing "the live database" cannot be done by
 * writing a different string, only by defeating a row count on a database that
 * really is empty.
 *
 * PHP has no package-private, so the factory is technically callable from anywhere;
 * an architecture test pins that only the template builder calls it, and the count
 * it demands is what makes a careless call fail rather than silently pass. The
 * database this names is a throwaway carrying the shadow prefix, dropped with the
 * clone — never a user-configured database.
 */
final readonly class VirginTemplate
{
    private function __construct(public string $database) {}

    /**
     * Mint a template from a database whose user tables have just been counted.
     *
     * `$rowsFound` is that count. A non-zero count is refused outright: it means the
     * database holds data, and cloning it would copy that data into the shadow. The
     * refusal is an exception rather than a three-valued result because there is no
     * safe way to continue — a shadow run is optional, and losing it costs nothing
     * next to cloning production.
     *
     * @internal to the shadow provisioning layer; the architecture test pins the callers
     *
     * @throws NotAVirginTemplate when the database holds any row at all
     */
    public static function verifiedEmpty(string $database, int $rowsFound): self
    {
        if ($rowsFound !== 0) {
            throw NotAVirginTemplate::holdingRows($database, $rowsFound);
        }

        return new self($database);
    }
}
