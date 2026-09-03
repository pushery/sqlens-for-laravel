<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard\Contracts;

use Illuminate\Database\Events\QueryExecuted;
use Pushery\SQLens\Guard\GuardProfile;

/**
 * A guardrail that judges executed queries, rather than one that flips a switch at boot.
 *
 * It is a SEPARATE contract from {@see RuntimeGuard} because the two are activated differently: a
 * strictness switch is set once and forgotten, while everything here shares ONE query listener. A
 * listener per guardrail would put N closures on the hot path of every query an application runs —
 * a runtime cost that grows with the feature, on a package whose whole promise is that it reads.
 */
interface QueryInspector
{
    /** Whether this profile asks for this inspection. */
    public function appliesTo(GuardProfile $profile): bool;

    /** Judge one executed query. Called on the query hot path, so it does no I/O of its own. */
    public function inspect(QueryExecuted $query, GuardProfile $profile): void;
}
