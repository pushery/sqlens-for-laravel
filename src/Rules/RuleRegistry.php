<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Exceptions\InvalidRule;
use Pushery\SQLens\Levels\Level;

/**
 * The immutable collection where every rule of a run is enumerated and filtered
 * over the four axes (suite ∩ level ∩ version window ∩ category). Registration
 * happens once at build; afterwards it is read-only, with a deterministic
 * iteration order by rule id.
 *
 * A duplicate rule id throws at build — never "last wins": a duplicate id is
 * public API damage that would make a finding unresolvable and hide a rule.
 *
 * Rules enter through the contract, not a class list in the core, so a
 * third-party rule pack registers the same way the package's own rules do. The
 * registry knows only the driver name the manager hands it — which rules belong
 * to pgsql vs mysql is the manager's job, not the registry's.
 *
 * Deprecation-aware: all() enumerates every rule (deprecated included, for docs
 * and completeness checks); executable() drops the deprecated ones. A deprecated
 * rule is LISTED, not EXECUTED — the no-op-plus-notice behavior is added later.
 *
 * The axis filters return a new registry (immutable, chainable, side-effect
 * free), so a run composes them in any order and gets the same subset.
 */
final readonly class RuleRegistry
{
    /**
     * @param  array<string, Rule>  $rules  keyed by rule id, ordered by id
     */
    private function __construct(private array $rules) {}

    /**
     * Build a registry from rules, deduplicating by id (a duplicate throws) and
     * fixing a deterministic iteration order by rule id.
     *
     * @param  iterable<Rule>  $rules
     */
    public static function fromRules(iterable $rules): self
    {
        $map = [];
        foreach ($rules as $rule) {
            if (isset($map[$rule->id()])) {
                throw InvalidRule::duplicateId($rule->id());
            }
            $map[$rule->id()] = $rule;
        }

        ksort($map);

        return new self($map);
    }

    /**
     * Every rule, deprecated included, ordered by id — the enumeration docs and
     * the metadata completeness check consume.
     *
     * @return list<Rule>
     */
    public function all(): array
    {
        return array_values($this->rules);
    }

    /**
     * The executable selection: deprecated rules are excluded. Order by id.
     *
     * @return list<Rule>
     */
    public function executable(): array
    {
        return array_values(array_filter(
            $this->rules,
            static fn (Rule $rule): bool => ! $rule->deprecation() instanceof RuleDeprecation,
        ));
    }

    /**
     * The complement of {@see self::executable()} — the rules that are registered and do not run.
     *
     * A deprecated rule is deliberately kept in `all()`: a baseline entry, an ignore list and a
     * suppression may still name it, and an upgrade that made those ids unknown would break other
     * people's configuration. What it must NOT be is invisible. Dropping it from the executable set
     * without saying so is a check that stopped running and a report that looks the same as before
     * — the silent green this package refuses everywhere else.
     *
     * @return list<Rule>
     */
    public function deprecated(): array
    {
        return array_values(array_filter(
            $this->rules,
            static fn (Rule $rule): bool => $rule->deprecation() instanceof RuleDeprecation,
        ));
    }

    /** Look up a rule by id — an unknown id in an ignore list is a config error, not a no-op. */
    public function get(string $id): ?Rule
    {
        return $this->rules[$id] ?? null;
    }

    /** A new registry keeping only the rules that run in the given suite. */
    public function forSuite(Suite $suite): self
    {
        return $this->keeping(static fn (Rule $rule): bool => SuiteMembership::runsIn($rule, $suite));
    }

    /** A new registry keeping only the rules the active level includes (cumulative). */
    public function atLevel(Level $active): self
    {
        return $this->keeping(static fn (Rule $rule): bool => $active->includes($rule->level()));
    }

    /** A new registry keeping only the rules in one of the given categories. */
    public function inCategories(Category ...$categories): self
    {
        return $this->keeping(static fn (Rule $rule): bool => in_array($rule->category(), $categories, true));
    }

    /** A new registry keeping only the rules whose version window matches the given server version. */
    public function matchingVersion(ServerVersion $version): self
    {
        return $this->keeping(static fn (Rule $rule): bool => $rule->versionWindow()->matches($version));
    }

    /**
     * @param  callable(Rule): bool  $keep
     */
    private function keeping(callable $keep): self
    {
        return new self(array_filter($this->rules, $keep));
    }
}
