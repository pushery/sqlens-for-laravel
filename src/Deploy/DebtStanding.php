<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * What the live catalog says about one recorded debt.
 *
 * Three answers, and the third is the whole reason this type exists.
 * {@see DebtReconciliation} compares a ledger against what a RUN FOUND, which can only ever produce
 * two: the debt was reported again, or it was not. That is enough for the repo side, where "not
 * reported" means "the migration no longer leaves it".
 *
 * On the live side it is not enough, because "not reported" hides two opposite situations. The
 * constraint exists and is validated — the project settled its debt. Or the object is not in the
 * catalog at all, and nobody can say whether the debt was paid, the table was dropped, or this run
 * simply could not see that schema. Collapsing those into one answer reports a settled debt on the
 * strength of an absence, which is the shape of "no silent green" this package refuses everywhere.
 */
enum DebtStanding: string
{
    /** The catalog still shows the debt. It is owed. */
    case StillOpen = 'still_open';

    /** The object is there and the debt is not. Somebody finished it. */
    case Resolved = 'resolved';

    /**
     * The object could not be found, so neither of the above can be said.
     *
     * NOT a resolution. A table that was dropped, a schema outside this run's scope, a role without
     * the privilege to see it — every one of them looks like this, and every one of them is a
     * different thing to go and check.
     */
    case ObjectNotFound = 'object_not_found';

    /** Whether this standing leaves the question open rather than answering it. */
    public function isUndetermined(): bool
    {
        return $this === self::ObjectNotFound;
    }

    /** The named reason an undetermined standing carries, or null when the answer is definite. */
    public function reason(): ?UndeterminedReason
    {
        return $this === self::ObjectNotFound ? UndeterminedReason::DebtObjectNotFound : null;
    }
}
