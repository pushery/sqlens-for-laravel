<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Reporting\RunContext;

/**
 * The result of one security run: every finding its halves produced, and which halves ran.
 *
 * The three booleans are not diagnostics. A report is only readable if a reader can tell "this half
 * found nothing" from "this half never happened", and the findings alone cannot say it — a run whose
 * migration capture was impossible carries a named finding about that, but a consumer branching on
 * counts would still read the total as the whole picture.
 *
 * The context is nullable because the audit half is the one that addresses an instance. When it
 * could not run, this run has no instance identity, no server version and no pooler verdict to
 * report — and the honest answer is that there is none, not one assembled from defaults.
 */
final readonly class SecurityOutcome
{
    /** @param  list<Finding>  $findings */
    public function __construct(
        public array $findings,
        public ?RunContext $context,
        public bool $auditReached,
        public bool $lintReached,
        /**
         * Whether the injection half read an analyse result.
         *
         * Defaulted, so every existing construction keeps its meaning: a run assembled before this
         * half existed did not reach it, and `false` says exactly that. A required parameter would
         * have forced dozens of call sites to answer a question they were never asked.
         */
        public bool $analyseReached = false,
    ) {}

    /**
     * Whether the run examined anything at all — the state the suite must never report as clean.
     *
     * The injection half is deliberately absent from this test, and its absence is load-bearing
     * rather than an oversight. That half cannot reach without a run context, and only a live half
     * establishes one — so `analyseReached` is true only where `auditReached` or `lintReached`
     * already is, and naming it here would add a clause that can never change the answer.
     */
    public function examinedNothing(): bool
    {
        return ! $this->auditReached && ! $this->lintReached;
    }
}
