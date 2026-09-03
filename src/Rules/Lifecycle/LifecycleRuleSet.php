<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Lifecycle;

use Pushery\SQLens\Contracts\Rule;

/**
 * The driver-neutral migration-lifecycle rules, in one deterministic order.
 *
 * These rules are the same on every engine — they judge what a migration DOES, not what
 * a server makes of a statement — so they live in Core and are the SINGLE source of the
 * lifecycle rules: each driver appends this set to its own engine-specific pack, and the
 * fixture suite judges against the same appended set, so what a user runs and what the
 * tests prove are the very same objects. A lifecycle rule is added HERE, once.
 *
 * Sorted by rule id rather than declaration order, for the same reason the engine packs
 * are: a report's finding order must not depend on which line a rule was added on.
 */
final readonly class LifecycleRuleSet
{
    /** @var list<Rule> */
    public array $rules;

    /** @param  list<Rule>  $rules */
    public function __construct(array $rules = [])
    {
        usort($rules, static fn (Rule $a, Rule $b): int => $a->id() <=> $b->id());

        $this->rules = $rules;
    }

    /**
     * The shipped lifecycle rule set, built for one project root — the one construction
     * dependency a rule has, so a finding's location is repo-relative.
     */
    public static function forProjectRoot(string $projectRoot): self
    {
        return new self([
            new DmlWithoutWhereRule($projectRoot),
            new DmlOnSchemaChangedTableRule($projectRoot),
            new DownMissingRule($projectRoot),
            new DownMoreDestructiveRule($projectRoot),
        ]);
    }

    /** @return list<Rule> */
    public function all(): array
    {
        return $this->rules;
    }
}
