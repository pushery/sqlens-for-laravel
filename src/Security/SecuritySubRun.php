<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Reporting\RunContext;
use Pushery\SQLens\Reporting\Suppression\SuppressedFinding;

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
 *
 * ## Why the suppressions travel too
 *
 * Each half resolves its own findings, so each half is also the only place that knows what it HID.
 * Without carrying that up, the aggregate report says "clean" and "clean after forty findings were
 * hidden" in the same words — and `sqlens:security` did exactly that, because it assembled its
 * result from finding lists alone. The visible findings answer what to fix; these answer who
 * decided something did not need fixing, which is the half an operator audits.
 */
final readonly class SecuritySubRun
{
    /**
     * @param  list<Finding>  $findings
     * @param  list<SuppressedFinding>  $suppressed
     */
    private function __construct(
        public array $findings,
        public ?RunContext $context,
        public bool $reached,
        public array $suppressed = [],
    ) {}

    /**
     * @param  list<Finding>  $findings
     * @param  list<SuppressedFinding>  $suppressed
     */
    public static function reached(array $findings, RunContext $context, array $suppressed = []): self
    {
        return new self($findings, $context, true, $suppressed);
    }

    /**
     * A sub-run that could not happen, carrying the finding that says so.
     *
     * Takes exactly one finding rather than a list: there is one reason a half did not run, and a
     * signature that accepted several would invite a caller to report a failure twice.
     *
     * It suppresses nothing, and that is a statement rather than a default: a half that never ran
     * resolved nothing, so an empty list here is the true count and not a missing one.
     */
    public static function failed(Finding $reason): self
    {
        return new self([$reason], null, false);
    }
}
