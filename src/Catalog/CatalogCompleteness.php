<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

/**
 * Whether a catalog reading saw everything it set out to.
 *
 * It sits ON the snapshot rather than in a log line, and that placement is the whole point. A
 * partial reading looks exactly like a complete one to every consumer downstream — the same object
 * collection, the same shape, fewer entries — so a rule finding nothing wrong in a half-read
 * catalog would report a clean audit of a database it barely saw. That is the silent green this
 * package is built against, and the only reliable defense is to make the answer travel with the
 * data rather than beside it.
 *
 * The backed values reach the JSON output and are public API from 1.0.
 */
enum CatalogCompleteness: string
{
    /** Everything in scope was read and understood. Skips, if any, were deliberate exclusions. */
    case Complete = 'complete';

    /**
     * Something in scope was not delivered — unreadable, not permitted, or not understood.
     *
     * A consumer may still use the snapshot; what it may not do is read "no findings" as "nothing
     * is wrong". Which objects are missing, and why, is in the snapshot's skip list.
     */
    case Partial = 'partial';
}
