<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Objects;

use Pushery\SQLens\Catalog\CatalogCompleteness;

/**
 * How much of one security object the reading actually saw.
 *
 * It sits ON the object rather than beside it, for the same reason
 * {@see CatalogCompleteness} sits on the snapshot: a partially read object
 * looks exactly like a fully read one to everything downstream — same type, same shape, fewer facts
 * — so a rule finding nothing wrong on a half-read role would report a clean verdict on an account
 * it barely saw.
 *
 * The set-level enum answers "did the reading see every object". This one answers "did it see every
 * FIELD of this object", and the two are genuinely different questions on a managed database:
 * `pg_roles` hands out every role while masking the password of each, so the set is complete and
 * every member of it is partial.
 *
 * The backed values reach the JSON output and are public API from 1.0.
 */
enum ReadabilityState: string
{
    /** Every field this object claims was read from the catalog. */
    case Complete = 'complete';

    /**
     * The object exists and was identified, but at least one field was withheld.
     *
     * The dangerous state, and the reason this enum exists: a partial object carries real values
     * beside missing ones, so nothing about it looks wrong. Which field is missing, and why, travels
     * in the reason.
     */
    case Partial = 'partial';

    /**
     * The object could not be read at all — it is known to exist (or to have existed) and nothing
     * beyond its identity was obtained.
     *
     * Distinct from "not in the set": an object that was never seen is a set-level skip, while this
     * is an object the reading names and cannot describe.
     */
    case Unreadable = 'unreadable';
}
