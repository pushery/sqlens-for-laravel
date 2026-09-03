<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Activity;

/**
 * One session that has been running longer than the request's threshold.
 *
 * It matters to a deploy for a reason that is not obvious: a long transaction does not have to be
 * holding a lock on the migration's table to hurt it. On PostgreSQL it holds back the oldest
 * transaction horizon, so `VACUUM` cannot reclaim anything and an online index build waits for it
 * to finish before it can even start — which turns a migration written to be safe into one that
 * hangs, with nothing in the lock views to explain why.
 *
 * **The query text is deliberately absent**, for the reason stated on {@see LockWait}: the state,
 * the duration and the relation are what a decision is made on; the statement is what carries
 * literals into a log.
 */
final readonly class LongRunningSession
{
    public function __construct(
        /** The session, as the server identifies it. */
        public string $session,
        /** How long it has been running, in milliseconds. */
        public int $runningForMs,
        /**
         * What it is doing, in the server's own vocabulary — `active`, `idle in transaction`, and
         * the like.
         *
         * Worth carrying because the two most alarming states look nothing alike: a long ACTIVE
         * query is somebody's slow report, while a long `idle in transaction` is a connection
         * somebody forgot to close, and the second is the one that silently freezes maintenance
         * across the whole database.
         */
        public string $state,
        /** The relation it is working on, where the server names one. */
        public ?string $relation = null,
    ) {}

    /** The stable sort key — longest first is a REPORTING choice, so ordering here stays by name. */
    public function sortKey(): string
    {
        return $this->session;
    }

    /** @return array{session: string, running_for_ms: int, state: string, relation: string|null} */
    public function toArray(): array
    {
        return [
            'session' => $this->session,
            'running_for_ms' => $this->runningForMs,
            'state' => $this->state,
            'relation' => $this->relation,
        ];
    }
}
