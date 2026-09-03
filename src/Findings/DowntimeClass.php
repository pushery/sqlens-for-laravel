<?php

declare(strict_types=1);

namespace Pushery\SQLens\Findings;

/**
 * The machine-readable bridge from a safety rule to a deploy decision: a class
 * a deploy script can consume directly.
 *
 * Carries a stable ordering (rewrite > blocking > online) for prioritizing in
 * the reporter and the agent fix guidance. The per-rule assignment happens later
 * (PostgreSQL, and MySQL matrix-driven: INSTANT/INPLACE/COPY →
 * online/blocking/rewrite); this enum is only the vocabulary.
 */
enum DowntimeClass: string
{
    case Online = 'online';
    case Blocking = 'blocking';
    case Rewrite = 'rewrite';

    /**
     * Severity ranking for prioritization: a full-table rewrite outranks a
     * blocking lock, which outranks an online change. Higher is worse.
     */
    public function rank(): int
    {
        return match ($this) {
            self::Online => 0,
            self::Blocking => 1,
            self::Rewrite => 2,
        };
    }

    /** Whether this class is at least as disruptive as the given one. */
    public function atLeastAsDisruptiveAs(self $other): bool
    {
        return $this->rank() >= $other->rank();
    }

    /**
     * Whether the operation disrupts anyone at all — everything except {@see self::Online}.
     *
     * A named predicate rather than a comparison against a case, because "not online" is a concept
     * several callers ask about and a `!== self::Online` at each of them is the same idea spelled
     * three ways. It also keeps the enum's CASES out of files that only need to know whether an
     * operation is free: the driver packs are guarded against naming a class directly, since a
     * downtime class named outside the classifier is a second classifier waiting to disagree.
     */
    public function disrupts(): bool
    {
        return $this !== self::Online;
    }

    /**
     * A one-line English description, used as the single source for the generated
     * rule docs and sqlens:agent-rules.
     */
    public function description(): string
    {
        return match ($this) {
            self::Online => 'Applies without blocking reads or writes.',
            self::Blocking => 'Takes a lock that blocks concurrent access for the duration.',
            self::Rewrite => 'Rewrites the whole table, holding a lock proportional to its size.',
        };
    }
}
