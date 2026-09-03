<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Exceptions\InvalidRule;

/**
 * The suite-axis filter: whether a rule runs in a given suite. Pure and
 * side-effect free — it only reads the rule's declared suites. The other three
 * axes (level, version window, category) have their own filters; the registry
 * composes all four.
 *
 * A rule that declares no suite is a configuration error, not a silent skip:
 * runsIn() throws InvalidRule rather than quietly returning false, so a rule can
 * never vanish from every run by declaring an empty suite list.
 */
final class SuiteMembership
{
    /**
     * Whether the rule runs in the given suite.
     *
     * @throws InvalidRule when the rule declares no suite
     */
    public static function runsIn(Rule $rule, Suite $suite): bool
    {
        if ($rule->suites() === []) {
            throw InvalidRule::withoutSuite($rule->id());
        }

        return in_array($suite, $rule->suites(), true);
    }
}
