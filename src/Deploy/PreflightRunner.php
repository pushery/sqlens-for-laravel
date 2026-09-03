<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Contracts\PreflightCheck;

/**
 * Runs the registered preflight checks and collects what they answered.
 *
 * ## Order is declared, not discovered
 *
 * The checks run in the order the registry lists them, and that order is part of the contract. Two
 * runs against an unchanged database must produce byte-identical reports, and a set iterated in
 * whatever order a container happened to build would produce the same findings in a different
 * sequence — which a diff reports as a change. Determinism is one of this package's three
 * principles and this is the cheapest place to lose it.
 *
 * ## A check that does not apply is not run
 *
 * `appliesTo()` is asked BEFORE `run()`, and a check that answers no produces no result. It is
 * listed separately as not applicable, and the distinction is the whole reason there is no fourth
 * outcome: "this does not apply to your database" and "this could not answer" are different
 * sentences that send a reader to different places.
 *
 * ## The budget stops the run, and stopping is an ANSWER
 *
 * When the deadline passes, the checks that have not run yet are reported `undetermined` with the
 * budget named — never silently omitted. A gate that quietly ran four of its nine checks and
 * reported a clean result is the worst thing this package could ship: it would be trusted exactly
 * as much as a complete one and would be worth nothing.
 */
final readonly class PreflightRunner
{
    /** @param list<PreflightCheck> $checks in the order they will run */
    public function __construct(private array $checks = []) {}

    public function run(PreflightContext $context): PreflightReport
    {
        $checks = $this->checks;

        // The sequencing is shared with the postdeploy verifier rather than written twice. Two
        // copies of these four rules would drift, and each copy would keep passing its own tests
        // while doing so — see CheckSequence for which of them makes that dangerous.
        return CheckSequence::run(
            array_map(static fn (PreflightCheck $check): string => $check->id(), $checks),
            static fn (int $at): bool => $checks[$at]->appliesTo($context->driver),
            static fn (): bool => $context->isExhausted(),
            static fn (int $at): CheckResult => $checks[$at]->run($context),
        );
    }

    /**
     * The checks this runner would execute, in order — for the report's own header.
     *
     * @return list<string>
     */
    public function registered(): array
    {
        return array_map(static fn (PreflightCheck $check): string => $check->id(), $this->checks);
    }
}
