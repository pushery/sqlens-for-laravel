<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Reporting\RunContext;

/**
 * What one half of a security run produced — and whether it happened at all.
 *
 * The `reached` flag is the whole reason this type exists rather than a bare finding list. A sub-run
 * that ran and found nothing and a sub-run that could not run both return no findings, and the two
 * are opposite answers: the first says the database is clean on that surface, the second says nobody
 * looked. A list cannot carry that difference, so it travels beside it.
 *
 * The context is nullable for the same reason and not as a convenience: only a sub-run that actually
 * addressed an instance has one to give.
 */
final readonly class SecuritySubRun
{
    /** @param  list<Finding>  $findings */
    private function __construct(
        public array $findings,
        public ?RunContext $context,
        public bool $reached,
    ) {}

    /** @param  list<Finding>  $findings */
    public static function reached(array $findings, RunContext $context): self
    {
        return new self($findings, $context, true);
    }

    /**
     * A sub-run that could not happen, carrying the finding that says so.
     *
     * Takes exactly one finding rather than a list: there is one reason a half did not run, and a
     * signature that accepted several would invite a caller to report a failure twice.
     */
    public static function failed(Finding $reason): self
    {
        return new self([$reason], null, false);
    }
}
