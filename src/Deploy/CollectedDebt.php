<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Severity\Severity;

/**
 * One recorded debt, with what the live catalog says about it and how long it has been outstanding.
 *
 * The three parts stay separate because they can each be unknown on their own. A debt whose object
 * the catalog cannot show still has a readable age; a debt that is plainly still open can carry a
 * `first_seen` this build cannot parse. Folding them into one verdict would let either absence
 * silence the other's answer — and a collector that reported less than it knew would be doing the
 * same thing as one that reported more.
 */
final readonly class CollectedDebt
{
    public function __construct(
        public DebtEntry $entry,
        public DebtStanding $standing,
        public DebtAge $age,
    ) {}

    /**
     * The severity this debt is worth, given what the finding already said and how old it is.
     *
     * An acknowledged debt does not escalate: somebody looked at it, decided to carry it, and wrote
     * down why. Age is the argument for caring more, and that argument has already been heard and
     * answered — escalating anyway would make the decision worthless and the report noisier every
     * month, which is how a project learns to stop reading it.
     *
     * An age this build could not read does not escalate either. A threshold applied to an unknown
     * number is a guess wearing a policy's clothes; the unreadable date is reported on its own.
     */
    public function severity(DebtThresholds $thresholds, Severity $base): Severity
    {
        if ($this->entry->state === DebtState::Acknowledged || ! $this->age->isKnown()) {
            return $base;
        }

        return $thresholds->escalate($base, (int) $this->age->days());
    }
}
