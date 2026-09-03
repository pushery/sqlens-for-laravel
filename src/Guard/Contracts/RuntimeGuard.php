<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard\Contracts;

use Pushery\SQLens\Guard\GuardProfile;

/**
 * One runtime guardrail: it says whether a profile asks for it, and it turns itself on.
 *
 * Two methods and no third, deliberately. There is no `deactivate()`, because nothing here is ever
 * turned off — a request that wanted the guardrail off simply never activated it, and a suite that
 * could toggle guardrails mid-process would be holding state across a request boundary that Octane
 * compatibility forbids.
 *
 * There is also no `name()`. The activation order comes from the registry, which is a written list
 * rather than a discovered one, so nothing needs to identify a guard at runtime.
 */
interface RuntimeGuard
{
    /**
     * Whether this profile asks for this guardrail.
     *
     * Asked separately from `activate()` so the manager can report what it turned on without having
     * turned anything on — and so a guard that applies to nothing costs one method call rather than
     * a listener.
     */
    public function appliesTo(GuardProfile $profile): bool;

    /** Turn it on. Called at most once per process, and only when `appliesTo()` said so. */
    public function activate(GuardProfile $profile): void;
}
