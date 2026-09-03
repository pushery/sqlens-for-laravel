<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Catalog\CatalogRequest;
use Pushery\SQLens\Catalog\CatalogSnapshot;
use Pushery\SQLens\Catalog\Usage\IndexUsageReading;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Reads a live database catalog into the one shape every suite downstream reasons about.
 *
 * It is the audit suite's counterpart to the capture layer: where a captor turns pending
 * MIGRATIONS into subjects, a reader turns what is ALREADY IN the database into them. One rule
 * engine, two sources — which is why the output is the same canonicalized `SchemaObject` view and
 * not a second, parallel model that would drift from the first.
 *
 * ## What an implementation must promise
 *
 * - **Read-only, and bounded.** A catalog read never takes a lock, never writes, and bounds its own
 *   session. An audit that becomes the incident it was auditing has failed at something more basic
 *   than correctness.
 * - **No silent gap.** Anything in scope that could not be delivered is a named skip on the
 *   snapshot, and the snapshot says so through its completeness. A reader that dropped an object
 *   quietly would produce a clean-looking audit of a database it barely saw.
 * - **Deterministic.** The same database and the same request produce a byte-identical snapshot.
 *   The snapshot type enforces the ordering; the reader must not add non-determinism of its own
 *   (no timestamps, no server-side ordering it does not control).
 *
 * The interface itself is driver-neutral by construction — no PDO, no connection, no SQL in the
 * signature. Which catalog relations answer the question is the driver's business, and keeping it
 * out of here is what lets the security readers and the statistics readers that come later be
 * siblings of this one rather than forks of it.
 */
interface CatalogReader
{
    /**
     * The kinds of schema object this reader can construct — the scope a caller cannot otherwise see.
     *
     * ## Why this has to be on the contract
     *
     * {@see CatalogRequest} carries a `types` filter whose empty value means "every type the reader
     * supports", and nothing said what that set is. So a caller asking for everything got whatever
     * the driver happened to implement, with no way to learn what that was — and the one caller for
     * whom that matters most is `sqlens:drift`, which answers the question "did this schema change".
     *
     * Measured before this method existed: the MySQL reader constructs six types and the PostgreSQL
     * reader nine, and NEITHER constructs {@see SchemaObjectType::Routine}. A drift run over a
     * database whose stored procedure had been edited therefore reported no findings, and
     * `DriftReport::isConclusive()` returned true — the honest mechanism was built, correct, and
     * never fed.
     *
     * ## This is scope, NOT a skip
     *
     * The distinction is load-bearing and the class docblock above already draws it: a named skip on
     * the snapshot means something IN SCOPE could not be delivered. A type this reader never reads is
     * not a failed reading, it is a reading nobody wrote yet — and folding the two together would
     * make every gate run permanently `undetermined`, which teaches a team to pass
     * `--allow-undetermined` forever and swallows the real, transient skips along with it.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function readableObjectTypes(): array;

    /** Read the catalog for the given scope. Never throws for an unreadable object — that is a skip. */
    public function read(CatalogRequest $request): CatalogSnapshot;

    /**
     * How often each index has been read, and since when the server has been counting.
     *
     * A SECOND accessor rather than more fields on the snapshot, because the two answers have
     * different properties. A snapshot is deterministic by contract; usage counters move while the
     * schema stands still, and the window they cover starts wherever the server last reset them.
     * Merging them would put a moving value inside the structure the drift comparison relies on
     * being still.
     *
     * It is on the CONTRACT rather than reachable through some driver-specific side door, and that
     * is the whole point of putting it here: a rule that queried the statistics views itself would
     * be a second code path into the same data, free to disagree with this one about scope,
     * privileges and degradation. An architecture test holds that — a rule naming `pg_stat_` or
     * `performance_schema` turns it red. The statistics reader the deploy suite grows later extends
     * this accessor rather than forking it.
     *
     * Never throws. A view the connecting role may not read, or an engine that does not keep these
     * counters, comes back as {@see IndexUsageReading::unavailable()} — because "nothing has been
     * scanned" and "nobody could look" are different statements, and a caller has to be able to
     * tell them apart.
     */
    public function indexUsage(CatalogRequest $request): IndexUsageReading;
}
