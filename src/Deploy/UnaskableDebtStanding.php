<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Deploy\Contracts\ResolvesDebtStanding;

/**
 * The resolver for an engine this build has no catalog question for.
 *
 * It answers {@see DebtStanding::Unaskable} to everything, which is the literal truth: the question
 * could not be put. That standing is undetermined and carries its own named reason, so a run on
 * such an engine reports every recorded debt as an open question rather than reporting nothing, and
 * without claiming, as it used to, that the catalog does not show the object.
 *
 * The alternative shapes were both worse. Returning null would make every caller invent its own
 * handling, and one of them would eventually invent silence. Answering `Resolved` would remove
 * entries from a committed file on the strength of an engine this build cannot even ask — the
 * quietest possible way to lose a project's account.
 */
final readonly class UnaskableDebtStanding implements ResolvesDebtStanding
{
    public function standingFor(DebtEntry $entry): DebtStanding
    {
        return DebtStanding::Unaskable;
    }
}
