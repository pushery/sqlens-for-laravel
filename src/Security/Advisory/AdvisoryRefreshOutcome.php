<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Advisory;

/**
 * What a refresh did, or why it did nothing.
 *
 * Never an exception, and never a bare boolean. A refresh that failed leaves the existing file
 * untouched — which is the right behavior and also completely invisible, because the file is
 * exactly as it was. So the outcome carries the sentence that says which of the several ways it
 * failed, and a caller renders it.
 */
final readonly class AdvisoryRefreshOutcome
{
    /**
     * @param  list<string>  $changes  one line per cycle that appeared, vanished or moved
     */
    private function __construct(
        public bool $written,
        public ?string $path,
        public array $changes,
        public ?string $reason,
    ) {}

    /** @param  list<string>  $changes */
    public static function written(string $path, array $changes): self
    {
        return new self(true, $path, $changes, null);
    }

    public static function refused(string $reason): self
    {
        return new self(false, null, [], $reason);
    }

    /**
     * A refresh that fetched valid data identical to what is already on disk.
     *
     * Distinguished from a write, because "nothing changed" and "something changed" are different
     * things to tell somebody who is about to review a commit — and a run that reported a write with
     * an empty diff would have them looking for a change that is not there.
     */
    public static function unchanged(string $path): self
    {
        return new self(false, $path, [], null);
    }

    public function succeeded(): bool
    {
        return $this->reason === null;
    }
}
