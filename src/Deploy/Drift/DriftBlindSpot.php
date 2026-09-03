<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * An object type one side could not read, and therefore a part of the schema this run did not
 * compare.
 *
 * ## Why this is a first-class part of the result and not a log line
 *
 * A comparison that could not see indexes and reported no index drift has said something false. The
 * whole point of the three-valued model is that "I looked and they match" and "I could not look"
 * are different answers, and only one of them is good news.
 *
 * So an unreadable type does not stop the run — the rest of the comparison is still worth having —
 * but it leaves this, and a caller that renders a drift report without rendering these is rendering
 * a clean bill of health it was never given.
 */
final readonly class DriftBlindSpot
{
    public function __construct(
        public SchemaObjectType $type,
        public DriftSide $side,
        public string $reason,
    ) {}

    public function sortKey(): string
    {
        return $this->type->value.':'.$this->side->value;
    }

    /** The sentence a report puts in front of a reader. */
    public function message(): string
    {
        return 'the '.$this->type->value.' objects of the '.$this->side->value
            .' side could not be read ('.$this->reason.'), so no '.$this->type->value
            .' was compared — this is not the same as finding no drift in them';
    }
}
