<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Contracts\Rule;

/**
 * The version axis of rule selection, the sibling of the level and category gates —
 * and the one place the fast path's "no live server" reality meets the rule set.
 *
 * The engine evaluates a rule's version window BEFORE it evaluates the subject, so a
 * rule can never fire outside the versions it was written for. This gate makes that
 * evaluation three-valued, exactly as the {@see Rule} contract requires:
 *
 *   - A KNOWN version (detected on a live server, or pinned via assume_server_version):
 *     a rule whose window matches runs; a rule whose window does not match produces NO
 *     finding — "not written for this version" is silence, correctly.
 *   - An UNKNOWN version (the fast path with no pin, an unreachable server): a
 *     version-INDEPENDENT rule still runs unrestricted, while a version-DEPENDENT rule
 *     cannot be judged and is surfaced as an undetermined finding by the caller — never
 *     a silent skip, and never a guess against a default version (pitfall 5).
 *
 * It is a pure selector over a rule LIST (the output of the level and category gates),
 * so the three axes compose in a fixed order and none bends another's semantics.
 */
final readonly class VersionRuleGate
{
    public function __construct(private ?ServerVersion $version) {}

    /**
     * The rules that RUN: every rule when the version is known and its window matches,
     * plus every version-independent rule when the version is unknown.
     *
     * @param  list<Rule>  $rules
     * @return list<Rule>
     */
    public function active(array $rules): array
    {
        // A known version selects rules through the registry's own window match — the
        // one version-comparison path, never a second copy of the logic.
        if ($this->version instanceof ServerVersion) {
            return RuleRegistry::fromRules($rules)->matchingVersion($this->version)->all();
        }

        return array_values(array_filter($rules, static fn (Rule $rule): bool => ! $rule->versionWindow()->isBounded()));
    }

    /**
     * The version-DEPENDENT rules that could not be judged because the version is
     * unknown — each becomes an undetermined finding, never a silent skip. Empty when
     * the version is known: a known version places every rule as run or not-applicable.
     *
     * @param  list<Rule>  $rules
     * @return list<Rule>
     */
    public function undetermined(array $rules): array
    {
        if ($this->version instanceof ServerVersion) {
            return [];
        }

        return array_values(array_filter($rules, static fn (Rule $rule): bool => $rule->versionWindow()->isBounded()));
    }
}
