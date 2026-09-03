<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

/**
 * Which seal a connection gets, for the engine it speaks.
 *
 * A contract rather than a function, because the mapping is the one piece of this that HAS to know
 * both engines — and the core must not. `src/Catalog` and `src/Console` are scanned for engine
 * vocabulary and would fail with the concrete classes imported; putting the choice behind this
 * interface keeps the knowledge where it belongs (`src/Drivers`) and lets everything else ask.
 *
 * It exists at all because the alternative is worse: a caller that picked its own defense is a
 * caller that can pick the WRONG one, and the failure that produces is a session which believes it
 * is sealed and is not.
 */
interface SessionDefenses
{
    /** The seal for this driver, or the safest available one when the driver is not recognized. */
    public function for(string $driver): SessionDefense;
}
