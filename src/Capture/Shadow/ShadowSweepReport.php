<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

/**
 * What an orphan sweep found and what it removed — kept apart on purpose.
 *
 * Old shadow databases are always REPORTED (a leak the user should know about);
 * they are only DROPPED behind the production guard, because dropping is a
 * database-mutating action. Separating the two makes "found but not removed" (guard
 * held, report-only) a first-class, visible outcome rather than a silent no-op.
 */
final readonly class ShadowSweepReport
{
    /**
     * @param  list<string>  $orphansFound  every stale shadow database detected, in the order listed
     * @param  list<string>  $dropped  the subset actually removed (empty when the guard held)
     */
    public function __construct(
        public array $orphansFound,
        public array $dropped,
    ) {}
}
