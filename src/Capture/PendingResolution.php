<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

/**
 * The three-valued answer to "which migrations are pending": either a resolved,
 * ordered list, or a named skip — never a bare empty list.
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
     * @param  ?string  $remedy  for a skip whose cure is one statement the resolver could name, that
     *                           statement in a sentence; null for every other answer
     */
    private function __construct(
        public array $migrations,
        public ?PendingSkipReason $skip,
        public ?string $remedy = null,
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

    /** The pending set could not be determined, for the named reason, and what cures it when known. */
    public static function skipped(PendingSkipReason $reason, ?string $remedy = null): self
    {
        return new self([], $reason, $remedy);
    }

    /**
     * The skip's description followed by its remedy, as a finding or a console line states it.
     *
     * Null for a resolved answer, which has nothing to explain.
     */
    public function skipText(): ?string
    {
        if (! $this->skip instanceof PendingSkipReason) {
            return null;
        }

        return $this->remedy === null ? $this->skip->description() : $this->skip->description().' '.$this->remedy;
    }

    public function isResolved(): bool
    {
        return ! $this->skip instanceof PendingSkipReason;
    }
}
