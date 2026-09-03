<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use LogicException;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Outcome;

/**
 * A verdict was asked to move in a direction nothing is allowed to move it.
 *
 * {@see Finding::settledBySecondReading()} is the ONLY way a finding's outcome changes after it is
 * built, and it goes one way: undetermined to fail, when an independent reading settles what the
 * first one could not decide. Everything else — a pass talked into a failure, a failure quietly
 * downgraded, a second promotion of something already settled — is refused here rather than
 * absorbed.
 *
 * A `LogicException` and not a reportable finding, deliberately: this cannot be caused by a database,
 * a configuration or a user. It is reachable only by code in this package calling the method on the
 * wrong finding, which is a defect to fix rather than a state to report.
 */
final class InvalidFindingPromotion extends LogicException
{
    public static function notUndetermined(string $ruleId, Outcome $outcome): self
    {
        return new self(sprintf(
            'Finding `%s` is `%s` and only an undetermined finding can be settled by a second '
            .'reading. A verdict that has been reached is not re-decided: promoting one would let a '
            .'later pass overwrite an earlier failure, which is the silent green this package exists '
            .'to refuse.',
            $ruleId,
            $outcome->value,
        ));
    }
}
