<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Analyse;

use Pushery\SQLens\Findings\Finding;

/**
 * What the analyse half produced: findings, or the one sentence saying why there are none.
 *
 * Two states rather than an empty list, because an empty list is exactly the ambiguity this package
 * exists to remove. A codebase nobody analyzed and a codebase with no raw SQL both hand back nothing,
 * and only one of them is good news.
 *
 * The reason is a SENTENCE and not a finding: the security runner already owns the shape a
 * did-not-run answer takes, and a second one built here would be a second spelling of the same
 * statement — which is how two halves of a report end up disagreeing about what "did not run" means.
 */
final readonly class AnalyseReading
{
    /** @param  list<Finding>  $findings */
    private function __construct(
        public array $findings,
        public ?string $reason,
    ) {}

    /** @param  list<Finding>  $findings */
    public static function of(array $findings): self
    {
        return new self($findings, null);
    }

    /**
     * The half did not run, and this is why.
     *
     * The sentence completes "the analyse half examined nothing, because …", so it is written as a
     * clause rather than a sentence of its own — the runner supplies the frame.
     */
    public static function didNotRun(string $because): self
    {
        return new self([], $because);
    }
}
