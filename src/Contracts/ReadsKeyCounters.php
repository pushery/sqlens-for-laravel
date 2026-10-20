<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Catalog\CatalogRequest;
use Pushery\SQLens\Catalog\Usage\KeyCounterReading;

/**
 * A catalog reader that can say how far the counter behind each primary key has got.
 *
 * A capability beside {@see CatalogReader} rather than a method on it. Adding a method to that
 * contract would break every reader written against it; a reader that does not implement this one
 * still works, and the rules that need the counters then report that they could not be read.
 *
 * Never throws. A role that may not see a counter's position, a lock that was not granted in time
 * or a view the server refuses come back inside the {@see KeyCounterReading}, as a withheld or
 * unread counter or as a reading that is not available at all.
 */
interface ReadsKeyCounters
{
    public function keyCounters(CatalogRequest $request): KeyCounterReading;
}
