<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Catalog\Activity\ActivityRequest;
use Pushery\SQLens\Catalog\Activity\ActivitySnapshot;
use Pushery\SQLens\Catalog\Activity\LockMode;

/**
 * Reads what the instance is DOING — the live half of a deploy preflight.
 *
 * The third reader sibling, beside {@see CatalogReader} ("what is there") and
 * {@see StatisticsReader} ("how big is it"). This one answers "is now a good moment", and it is the
 * only one of the three whose answer is worthless a minute later. That is why it is a separate
 * contract rather than more fields on either: both of those promise a deterministic snapshot of a
 * standing world, and merging a moving value into one would put motion inside the structure a drift
 * comparison relies on being still.
 *
 * ## What an implementation must promise
 *
 * - **State views only.** Locks, sessions and replication come from the server's own state views.
 *   No user table is read, and `EXPLAIN` is never sent — it runs the planner over a real query
 *   against a real instance, which is work the target database does on the gate's behalf at the one
 *   moment nobody wants extra load on it. Held by the statement allowlist, not by this sentence.
 * - **Metadata, never statements.** The relation, the duration, the mode and the state are what a
 *   decision is made on. The query text is what carries literals — an address, a token, a customer
 *   name — into a report and into whatever log that report is pasted into. It is not read.
 * - **Read-only and bounded**, inside the share the request grants. A preflight that became the
 *   incident it was checking for has failed at something more basic than correctness.
 * - **No silent gap, and no silently DROPPED ROW.** A view that could not be read is a named skip.
 *   A lock whose mode has no neutral name is reported ANYWAY, carrying the server's own spelling —
 *   the snapshot turns that into its own skip. Losing it during the mapping would delete a blocking
 *   lock from the picture and report calm at the worst possible moment.
 * - **Never throws for an unreadable source.** "Nothing is blocking" and "nobody could look" are
 *   different statements, and the difference is the entire value of this reading.
 *
 * Driver-neutral by construction: no PDO, no connection, no SQL in the signature, and no engine's
 * lock vocabulary — {@see LockMode} is what both engines map onto.
 */
interface ActivityReader
{
    /**
     * Read the instance's current activity.
     *
     * Never throws for a source it cannot read — that is a skip on the returned snapshot, and the
     * snapshot then says its silence cannot be trusted.
     */
    public function read(ActivityRequest $request): ActivitySnapshot;
}
