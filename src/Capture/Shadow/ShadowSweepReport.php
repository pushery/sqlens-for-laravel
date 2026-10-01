<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

/**
 * What an orphan sweep found and what it removed — kept apart on purpose.
 *
 * Old shadow databases are always REPORTED (a leak the user should know about);
 * they are only DROPPED behind the production guard, because dropping is a
 * database-mutating action. Separating the two makes "found but not removed" (guard
 * held, report-only) a first-class, visible outcome rather than a silent no-op.
 *
 * A sweep that could not even list the shadow databases is a third outcome, and it is
 * not an empty one: nobody knows what is left, so it says so rather than reading as
 * a server with nothing to clean up.
 */
final readonly class ShadowSweepReport
{
    /**
     * @param  list<string>  $orphansFound  every stale shadow database detected, in the order listed
     * @param  list<string>  $dropped  the subset actually removed (empty when the guard held)
     * @param  bool  $listed  false when the shadow databases could not be listed at all
     */
    public function __construct(
        public array $orphansFound,
        public array $dropped,
        public bool $listed = true,
    ) {}

    /** A sweep that could not list the shadow databases, so what is left is unknown. */
    public static function unlisted(): self
    {
        return new self([], [], false);
    }

    /**
     * The orphans found and not removed: the guard held, or the drop failed.
     *
     * @return list<string>
     */
    public function kept(): array
    {
        return array_values(array_diff($this->orphansFound, $this->dropped));
    }

    /** Whether the sweep has anything to tell a reader: an orphan it found, or a listing that failed. */
    public function hasAnythingToReport(): bool
    {
        return ! $this->listed || $this->orphansFound !== [];
    }

    /** Two sweeps as one: every name either found or removed, and unlisted if either was. */
    public function merge(self $other): self
    {
        return new self(
            array_values(array_unique([...$this->orphansFound, ...$other->orphansFound])),
            array_values(array_unique([...$this->dropped, ...$other->dropped])),
            $this->listed && $other->listed,
        );
    }
}
