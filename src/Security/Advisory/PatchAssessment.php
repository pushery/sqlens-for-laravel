<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Advisory;

/**
 * One verdict about one server's version, with everything a reader needs to act on it.
 *
 * The verdict alone would be unusable. "Past support" without the cycle sends somebody to check
 * which major they are on; without the end date it does not say how long it has been true; and
 * without the file it was judged from, an operator who refreshed the data and still sees the same
 * answer has nowhere to look. So the assessment carries all four, and the rule renders them.
 */
final readonly class PatchAssessment
{
    public function __construct(
        public PatchVerdict $verdict,
        /** The version string exactly as the server named it, build suffix and all. */
        public string $reported,
        /** The cycle this was read as, or null when the string could not be read at all. */
        public ?string $cycle,
        /** The data's entry for that cycle, or null when it has none. */
        public ?EolCycle $entry,
        public EolData $data,
    ) {}

    /**
     * One sentence naming the evidence behind the verdict.
     *
     * On every finding rather than only on the failures, because the question a reader asks of a
     * pass is the same one they ask of a failure: how does it know? A run judged from a stale file
     * looks identical to one judged from a fresh one until the file says when it was compiled.
     */
    public function provenance(): string
    {
        return sprintf(
            'judged from the %s end-of-life data at "%s", compiled %s',
            $this->data->source->value,
            $this->data->path,
            $this->data->compiledOn,
        );
    }
}
