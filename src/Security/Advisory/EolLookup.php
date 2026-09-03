<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Advisory;

/**
 * What a lookup of the end-of-life data produced: the data, or a named reason it is unavailable.
 *
 * Three-valued at the boundary, which is why this exists at all rather than the repository simply
 * returning `?EolData`. A null would collapse four distinct situations — no file anywhere, a
 * configured path that does not exist, a file that is not readable, a file whose shape or schema
 * version this build does not understand — into one, and each of those is fixed somewhere else.
 * "Unavailable" without the reason sends somebody to check the wrong thing.
 *
 * It never carries an exception. A missing advisory file must not take a security run down: the
 * run has plenty else to report, and a crash would lose all of it over one absent artifact.
 */
final readonly class EolLookup
{
    private function __construct(
        public ?EolData $data,
        /** Present exactly when {@see $data} is null; a sentence naming the path and the failure. */
        public ?string $reason,
    ) {}

    public static function found(EolData $data): self
    {
        return new self($data, null);
    }

    public static function unavailable(string $reason): self
    {
        return new self(null, $reason);
    }

    public function isAvailable(): bool
    {
        return $this->data instanceof EolData;
    }
}
