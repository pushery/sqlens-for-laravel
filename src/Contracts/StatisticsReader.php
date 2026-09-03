<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Catalog\Statistics\StatisticsRequest;
use Pushery\SQLens\Catalog\Statistics\StatisticsSnapshot;

/**
 * Reads what the server believes about the SIZE of the objects a run already has findings about.
 *
 * The sibling of {@see CatalogReader}, not a fork of it. A catalog reading answers "what is there";
 * this one answers "how big is it" — a different question with different properties, which is why
 * it is a second contract rather than more fields on the first. The catalog reading is meant to be
 * a still picture; sizes and row counts move while the schema stands still, and merging them would
 * put a moving value inside the structure the drift comparison relies on being still. The same
 * reasoning already gave `CatalogReader::indexUsage()` its own accessor.
 *
 * The contract exists BEFORE either implementation, and deliberately so. Two readers written
 * against no shared shape produce two statistics views that disagree about scope, about what a
 * skip means, and about whether a missing number is a zero — and the severity escalation that
 * consumes them would have to know which engine it was talking to in order to read its own input.
 *
 * ## What an implementation must promise
 *
 * - **Read-only, and bounded.** A statistics reading takes no lock, writes nothing, and bounds its
 *   own session inside the share the request grants it. It runs immediately before a deploy, which
 *   is the worst possible moment to become the incident it was measuring.
 * - **Only what was asked for.** The request names its objects and an implementation reads those.
 *   Widening the scope because a broader query was easier to write is how a targeted lookup becomes
 *   a production sweep.
 * - **No silent gap.** Anything asked for and not delivered is a named skip on the snapshot, which
 *   then reports itself partial. A number that could not be read is absent, never zero — the whole
 *   consumer here is a weighting, and a zero would weight a large table as a small one.
 * - **Never throws for an unreadable object.** An engine that does not keep the statistic, a role
 *   that may not read the view, a budget that ran out: each is a skip with a reason, because
 *   "nothing to report" and "nobody could look" are different statements and a caller has to be
 *   able to tell them apart.
 * - **Deterministic.** The same database and the same request produce a byte-identical snapshot.
 *   The snapshot type enforces the ordering; an implementation must add no non-determinism of its
 *   own — no wall-clock stamps, no reliance on a server-side order it does not control.
 *
 * The interface is driver-neutral by construction: no PDO, no connection, no SQL in the signature.
 * Which catalog relations answer the question is the driver's business, and keeping it out of here
 * is what lets the two implementations be siblings rather than forks.
 */
interface StatisticsReader
{
    /**
     * Read statistics for the objects the request names.
     *
     * Never throws for an object it cannot read — that is a skip on the returned snapshot.
     */
    public function read(StatisticsRequest $request): StatisticsSnapshot;
}
