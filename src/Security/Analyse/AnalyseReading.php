<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Analyse;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\UndeterminedReason;

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
        /** The undetermined reason a did-not-run answer carries, and null for a reading. */
        public ?UndeterminedReason $cause = null,
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
     *
     * For a half nothing set up to read a result, so its cause is `not_configured`.
     */
    public static function didNotRun(string $because): self
    {
        return new self([], $because, UndeterminedReason::NotConfigured);
    }

    /**
     * The half was set up to read a result and could not read the one it was pointed at.
     *
     * Its cause is `sub_run_failed`: a missing, unreadable or foreign file is a thing to fix, where a
     * half switched off is a thing somebody decided. The clause is written as for didNotRun().
     */
    public static function couldNotRead(string $because): self
    {
        return new self([], $because, UndeterminedReason::SubRunFailed);
    }
}
