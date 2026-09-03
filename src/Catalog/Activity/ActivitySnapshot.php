<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Activity;

use Pushery\SQLens\Catalog\CatalogCompleteness;
use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Catalog\SkipReason;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * One reading of what the instance is DOING right now: who is waiting on a lock, who has been
 * running too long, and how far the replicas are behind.
 *
 * The sibling of the catalog and statistics snapshots, and the one with the sharpest failure mode.
 * A catalog reading that came back short produces an audit that missed something; an activity
 * reading that came back short produces the sentence "nothing is blocking, go ahead" — at the exact
 * moment somebody is deciding whether to run a migration against production.
 *
 * **Empty is not calm.** That is the property everything here is arranged around. A snapshot with no
 * lock waits and no long-running sessions is the shape of a healthy server AND the shape of a
 * reading whose views were all withheld, so the two are told apart by the skips rather than by the
 * contents. Completeness is derived from those skips and never asserted, so an optimistic reader
 * cannot report `complete` while its own skip list disagrees.
 *
 * ## An unmappable lock mode cannot be dropped, and the constructor is what makes that true
 *
 * A row whose mode this build has no neutral name for is the row most worth seeing: an unfamiliar
 * mode means a newer engine, a provider extension, or a lock type nobody here has reasoned about.
 * The natural place to lose it is the mapping — a `match` with no arm, a filter that keeps what it
 * understood — and losing it deletes a blocking lock from the picture.
 *
 * So the row arrives carrying the server's own spelling, and THIS constructor adds the
 * `unmapped_lock_mode` skip itself. A reader cannot forget to, and a reader cannot decline to: the
 * normative rule is enforced by the type rather than stated in a docblock somebody has to read.
 *
 * ## Determinism
 *
 * Every collection is sorted here rather than left to whichever order the server's view returned.
 * Activity genuinely changes between readings — that is what it is — but two readings of the same
 * moment must still serialize identically, or a diff between a preflight and its retry reports the
 * ordering of a query plan as a change in the world.
 */
final readonly class ActivitySnapshot
{
    /** @var list<LockWait> */
    public array $lockWaits;

    /** @var list<LongRunningSession> */
    public array $longRunningSessions;

    /** @var list<ReplicationState> */
    public array $replication;

    /** @var list<CatalogSkip> */
    public array $skips;

    public CatalogCompleteness $completeness;

    /**
     * @param  list<LockWait>  $lockWaits
     * @param  list<LongRunningSession>  $longRunningSessions
     * @param  list<ReplicationState>  $replication
     * @param  list<CatalogSkip>  $skips
     */
    public function __construct(
        public ActivityRequest $request,
        array $lockWaits = [],
        array $longRunningSessions = [],
        array $replication = [],
        array $skips = [],
    ) {
        usort($lockWaits, static fn (LockWait $a, LockWait $b): int => $a->sortKey() <=> $b->sortKey());
        usort($longRunningSessions, static fn (LongRunningSession $a, LongRunningSession $b): int => $a->sortKey() <=> $b->sortKey());
        usort($replication, static fn (ReplicationState $a, ReplicationState $b): int => $a->sortKey() <=> $b->sortKey());

        foreach ($this->unmappedSkipsFor($lockWaits) as $skip) {
            $skips[] = $skip;
        }

        usort($skips, static fn (CatalogSkip $a, CatalogSkip $b): int => $a->sortKey() <=> $b->sortKey());

        $this->lockWaits = $lockWaits;
        $this->longRunningSessions = $longRunningSessions;
        $this->replication = $replication;
        $this->skips = $skips;
        $this->completeness = $this->completenessOf($skips);
    }

    /** Whether anything the reading set out to see went unseen. */
    public function isPartial(): bool
    {
        return $this->completeness === CatalogCompleteness::Partial;
    }

    /**
     * The skips where something went UNREAD, as opposed to being deliberately excluded.
     *
     * @return list<CatalogSkip>
     */
    public function gaps(): array
    {
        return array_values(array_filter(
            $this->skips,
            static fn (CatalogSkip $skip): bool => $skip->reason->leavesTheReadingIncomplete(),
        ));
    }

    /**
     * Whether this reading is safe to read silence from.
     *
     * The one accessor a preflight must pass through before concluding anything from an empty
     * snapshot, and it is phrased as a question about the READING rather than about the server for
     * exactly that reason. `isPartial()` answers the same fact; this name is what makes the wrong
     * use read wrongly at the call site.
     */
    public function silenceIsTrustworthy(): bool
    {
        return ! $this->isPartial();
    }

    /**
     * The lock waits whose mode this build could not name.
     *
     * Kept reachable rather than only counted, because the raw modes are what a later mapping is
     * written from — and because a reader of a partial preflight deserves to see WHICH lock could
     * not be classified rather than only that one could not.
     *
     * @return list<LockWait>
     */
    public function unmappedLockWaits(): array
    {
        return array_values(array_filter($this->lockWaits, static fn (LockWait $wait): bool => ! $wait->isMapped()));
    }

    /**
     * The lock waits touching a relation this deploy is about.
     *
     * @return list<LockWait>
     */
    public function lockWaitsInFocus(): array
    {
        return array_values(array_filter(
            $this->lockWaits,
            fn (LockWait $wait): bool => $this->request->focusesOn($wait->relation),
        ));
    }

    /** A stable digest of this reading, request included. */
    public function hash(): string
    {
        return hash('sha256', $this->serialize());
    }

    /** The canonical serialization — the one a hash is taken over. */
    public function serialize(): string
    {
        return json_encode($this->toArray(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * @return array{request: array<string, mixed>, completeness: string, lock_waits: list<array<string, mixed>>, long_running: list<array<string, mixed>>, replication: list<array<string, mixed>>, skips: list<array<string, mixed>>}
     */
    public function toArray(): array
    {
        return [
            'request' => $this->request->toArray(),
            'completeness' => $this->completeness->value,
            'lock_waits' => array_map(static fn (LockWait $w): array => $w->toArray(), $this->lockWaits),
            'long_running' => array_map(static fn (LongRunningSession $s): array => $s->toArray(), $this->longRunningSessions),
            'replication' => array_map(static fn (ReplicationState $r): array => $r->toArray(), $this->replication),
            'skips' => array_map(static fn (CatalogSkip $s): array => $s->toArray(), $this->skips),
        ];
    }

    /**
     * One named skip per lock wait this build could not classify.
     *
     * Per ROW rather than one summary skip, so the raw mode and the relation travel with the reason.
     * A single "some modes were unmapped" entry would be true and useless: the whole point is that
     * somebody can go and look at the one lock nobody has a name for.
     *
     * @param  list<LockWait>  $lockWaits
     * @return list<CatalogSkip>
     */
    private function unmappedSkipsFor(array $lockWaits): array
    {
        $skips = [];

        foreach ($lockWaits as $wait) {
            if ($wait->isMapped()) {
                continue;
            }

            $skips[] = CatalogSkip::for(
                SchemaObjectType::Table,
                $wait->relation,
                SkipReason::UnmappedLockMode,
                sprintf(
                    'the server reported a lock in mode "%s", which this build has no neutral name '
                    .'for. The wait is REPORTED anyway — an unfamiliar mode is one nobody has '
                    .'reasoned about, which makes it more worth seeing than any mode that maps.',
                    $wait->rawMode,
                ),
            );
        }

        return $skips;
    }

    /** @param  list<CatalogSkip>  $skips */
    private function completenessOf(array $skips): CatalogCompleteness
    {
        $unread = array_any($skips, static fn (CatalogSkip $skip): bool => $skip->reason->leavesTheReadingIncomplete());

        return $unread ? CatalogCompleteness::Partial : CatalogCompleteness::Complete;
    }
}
