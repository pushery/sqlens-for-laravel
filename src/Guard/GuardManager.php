<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard;

use Pushery\SQLens\Guard\Contracts\RuntimeGuard;

/**
 * The one place guard is armed: it takes the resolved profile and activates the guardrails it asks
 * for, in a written order.
 *
 * ## The registry is a LIST, not a scan
 *
 * Auto-discovery over a directory would make the activation order a property of the filesystem, and
 * two applications on two machines would arm the same profile in two different orders. Nothing here
 * currently depends on that order — and the moment something does, the difference would be a bug
 * nobody can reproduce. A list is one line longer per guard and cannot drift.
 *
 * ## It holds no state and watches nothing
 *
 * The manager activates and is done. It counts nothing, keeps nothing between requests, and never
 * opens a database connection of its own — `sqlens:postdeploy` is not monitoring and neither is
 * this. What each guardrail does after activation is that guardrail's business.
 */
final readonly class GuardManager
{
    /** @param list<RuntimeGuard> $guards in the order they will be activated */
    public function __construct(private array $guards = []) {}

    /**
     * Arm everything this profile asks for, and answer which guards that was.
     *
     * The return value is what makes the "off is absent, not cheap" promise testable: an arm can
     * assert that a null profile activated NOTHING without reaching into a container to count
     * listeners.
     *
     * @return list<string> the class names activated, in activation order
     */
    public function arm(?GuardProfile $profile): array
    {
        if (! $profile instanceof GuardProfile) {
            return [];
        }

        $armed = [];

        foreach ($this->guards as $guard) {
            if (! $guard->appliesTo($profile)) {
                continue;
            }

            $guard->activate($profile);
            $armed[] = $guard::class;
        }

        return $armed;
    }

    /** @return list<string> every registered guard, whether or not a profile wants it */
    public function registered(): array
    {
        return array_map(static fn (RuntimeGuard $guard): string => $guard::class, $this->guards);
    }
}
