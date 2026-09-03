<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

/**
 * The three-valued answer to "which migrations are pending": either a resolved,
 * ordered list, or a NAMED skip — never a bare empty list.
 *
 * A resolved result with an empty list is a real, honest answer ("nothing is
 * pending"). A skip is a different answer ("I could not tell"), and the type keeps
 * the two apart the way `FindingStatus` does for a check: the constructor is
 * private and a skip cannot be built without a reason, so the dangerous collapse of
 * "checked nothing" into "found nothing" cannot happen by accident.
 */
final readonly class PendingResolution
{
    /**
     * @param  list<PendingMigration>  $migrations
     */
    private function __construct(
        public array $migrations,
        public ?PendingSkipReason $skip,
    ) {}

    /**
     * A resolved pending set — possibly empty, which honestly means "nothing is
     * pending", never "could not tell".
     *
     * @param  list<PendingMigration>  $migrations
     */
    public static function resolved(array $migrations): self
    {
        return new self($migrations, null);
    }

    /** The pending set could not be determined, for the named reason. */
    public static function skipped(PendingSkipReason $reason): self
    {
        return new self([], $reason);
    }

    public function isResolved(): bool
    {
        return ! $this->skip instanceof PendingSkipReason;
    }
}
