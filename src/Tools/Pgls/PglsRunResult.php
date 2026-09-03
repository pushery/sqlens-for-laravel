<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Pgls;

/**
 * What one `dblint` run produced: a report, or a named reason there is none.
 *
 * Three-valued the way everything here is. "No findings" and "no report" are the two states a
 * boolean would merge, and merging them is how a tool that never reached the database comes to
 * read as a clean schema — which is this adapter's most likely failure, not a remote one.
 */
final readonly class PglsRunResult
{
    private function __construct(
        /** @var list<PglsRawFinding> */
        public array $findings,
        public ?PglsFailureReason $failure = null,
        /**
         * A short English sentence naming what happened — the exit code, the timeout, the entry
         * that would not read. Safe to show: it is composed here from facts about the run, and the
         * tool's own stderr reaches it only through the runner's redaction.
         */
        public string $detail = '',
    ) {}

    /** @param  list<PglsRawFinding>  $findings */
    public static function completed(array $findings): self
    {
        return new self($findings);
    }

    public static function failed(PglsFailureReason $reason, string $detail): self
    {
        return new self([], $reason, $detail);
    }

    /** Whether a report exists — an empty one included. */
    public function produced(): bool
    {
        return ! $this->failure instanceof PglsFailureReason;
    }
}
