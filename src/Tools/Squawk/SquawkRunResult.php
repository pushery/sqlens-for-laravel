<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Squawk;

/**
 * What one Squawk run produced: a report, or a named reason there is none.
 *
 * Three-valued the way everything here is. "No findings" and "no report" are the two states a
 * boolean would merge, and merging them is how a tool that never ran comes to read as a clean
 * migration.
 */
final readonly class SquawkRunResult
{
    private function __construct(
        /** @var list<SquawkRawFinding> */
        public array $findings,
        public ?SquawkFailureReason $failure = null,
        /**
         * A short English sentence naming what happened — the exit code, the timeout, the entry
         * that would not read. Safe to show: it is composed here from facts about the run, and
         * the tool's own stderr reaches it only through the runner's redaction.
         */
        public string $detail = '',
    ) {}

    /** @param  list<SquawkRawFinding>  $findings */
    public static function completed(array $findings): self
    {
        return new self($findings);
    }

    public static function failed(SquawkFailureReason $reason, string $detail): self
    {
        return new self([], $reason, $detail);
    }

    /** Whether a report exists — an empty one included. */
    public function produced(): bool
    {
        return ! $this->failure instanceof SquawkFailureReason;
    }
}
