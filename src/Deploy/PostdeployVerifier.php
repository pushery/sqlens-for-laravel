<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Contracts\PostdeployCheck;
use Pushery\SQLens\Deploy\Contracts\ProducesDebt;

/**
 * Runs the registered post-deploy checks once, and ends.
 *
 * ## Once is a structural property here, not a promise
 *
 * `sqlens:postdeploy` is not monitoring. There is no `--watch`, no daemon, no scheduler entry and no
 * history: this class has no loop, no state between calls and no way to be asked twice. That is the
 * non-goal made unbuildable rather than merely documented — a verifier that KEPT anything would be
 * the first half of the monitoring product this package deliberately is not.
 *
 * ## Order is declared, not discovered
 *
 * The checks run in the order the registry lists them. Two runs against an unchanged catalog must
 * produce byte-identical reports, and a set iterated in whatever order a container happened to
 * build would produce the same findings in a different sequence — which a diff reports as a change.
 *
 * The sequencing itself lives in {@see CheckSequence}, shared with the preflight runner, so the four
 * rules that decide whether a report can be trusted cannot drift between the two moments.
 */
final readonly class PostdeployVerifier
{
    /** @param list<PostdeployCheck> $checks in the order they will run */
    public function __construct(private array $checks = []) {}

    public function verify(PostdeployContext $context): PreflightReport
    {
        $checks = $this->checks;

        return CheckSequence::run(
            array_map(static fn (PostdeployCheck $check): string => $check->id(), $checks),
            static fn (int $at): bool => $checks[$at]->appliesTo($context->driver),
            static fn (): bool => $context->isExhausted(),
            static fn (int $at): CheckResult => $checks[$at]->run($context),
        );
    }

    /**
     * The checks this verifier would execute, in order — for the report's own header.
     *
     * @return list<string>
     */
    public function registered(): array
    {
        return array_map(static fn (PostdeployCheck $check): string => $check->id(), $this->checks);
    }

    /**
     * The checks that claim a lasting debt, as objects rather than ids.
     *
     * The registrar needs the OBJECT: it asks each claimant for its kind and, per finding, for the
     * reference the debt is about. Handing back ids the way {@see self::registered()} does would
     * force the caller to rebuild the mapping from somewhere, and "somewhere" would be a second
     * list of which checks produce debt — complete on the day it was written.
     *
     * Most checks are not here and that is the contract's whole point: silence means no debt.
     *
     * @return list<ProducesDebt>
     */
    public function claimants(): array
    {
        return array_values(array_filter(
            $this->checks,
            static fn (PostdeployCheck $check): bool => $check instanceof ProducesDebt,
        ));
    }
}
