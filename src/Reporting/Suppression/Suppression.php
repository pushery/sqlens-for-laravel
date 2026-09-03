<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Suppression;

/**
 * Why a finding is hidden, and by whom.
 *
 * A suppression without a named source and a reason is a bug, not a feature: it
 * is indistinguishable from a finding that never happened, which is the silent
 * green this whole package is built against. So both fields are mandatory and
 * both travel all the way into the console balance and the JSON envelope.
 *
 * `until` is a revisit HINT carried over from an annotation — a date or a version
 * someone wrote down. It never expires anything on its own; a suppression that
 * reactivated itself with no notice would be exactly the silent change this
 * package refuses.
 */
final readonly class Suppression
{
    public function __construct(
        public string $source,
        public string $reason,
        public ?string $until = null,
        public bool $undeterminedAllowed = false,
    ) {}

    /**
     * @return array{source: string, reason: string, until: string|null, undetermined_allowed: bool}
     */
    public function toArray(): array
    {
        return [
            'source' => $this->source,
            'reason' => $this->reason,
            'until' => $this->until,
            // Marked explicitly: hiding a check that could not RUN is a different
            // and much stronger statement than hiding a finding, so it never looks
            // like an ordinary suppression.
            'undetermined_allowed' => $this->undeterminedAllowed,
        ];
    }
}
