<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Activity;

/**
 * How far behind one replica is, as far as the primary will say.
 *
 * A deploy-time question rather than an operational one: a migration that runs on the primary
 * reaches the replicas whenever they catch up, so a project reading from replicas is running
 * against the OLD schema for exactly as long as the lag lasts. On a large table that can be
 * minutes, and the failures it produces during that window — a column that does not exist yet —
 * look like application bugs rather than like a deploy still in progress.
 *
 * Both measures are carried because neither answers on its own. Bytes say how much work is left and
 * are always available; seconds say how long that will take and are the number a human decides on,
 * but a replica with nothing to do reports zero seconds whether it is healthy or disconnected.
 */
final readonly class ReplicationState
{
    public function __construct(
        /** The replica, as the primary names it. */
        public string $replica,
        /**
         * Its connection state in the server's own vocabulary — `streaming`, `catchup`, and so on.
         *
         * The field that keeps a zero lag honest: a disconnected replica is not caught up, it is
         * gone, and both can report the same number.
         */
        public string $state,
        /** How far behind in bytes, or null when the server does not report it. */
        public ?int $lagBytes = null,
        /** How far behind in milliseconds, or null when the server does not report it. */
        public ?int $lagMs = null,
    ) {}

    /**
     * Whether this replica is actually receiving changes.
     *
     * Asked as a question about the CONNECTION rather than about the lag, because a lag of zero
     * means "caught up" and "not connected" equally well, and only one of those is good news.
     */
    public function isStreaming(): bool
    {
        return $this->state === 'streaming';
    }

    /** The stable sort key. */
    public function sortKey(): string
    {
        return $this->replica;
    }

    /** @return array{replica: string, state: string, lag_bytes: int|null, lag_ms: int|null} */
    public function toArray(): array
    {
        return [
            'replica' => $this->replica,
            'state' => $this->state,
            'lag_bytes' => $this->lagBytes,
            'lag_ms' => $this->lagMs,
        ];
    }
}
