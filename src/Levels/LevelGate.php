<?php

declare(strict_types=1);

namespace Pushery\SQLens\Levels;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Rules\RuleRegistry;

/**
 * The strictness gate, in Larastan's semantics: level `n` activates every rule at
 * `level <= n`, cumulatively. The whole rule catalog is one dial a project turns
 * up over time.
 *
 * The one exception is the axis separation this gate exists to anchor: security and
 * privacy model RISK, not strictness appetite, so they are gated by their own
 * severity axis and IGNORE the level gate entirely — a level-0 run can, and must be
 * able to, still report a critical security finding. Filtering them out by level
 * would collapse two orthogonal axes into one.
 *
 * "No silent green" is structural here: a rule the level hides does NOT become a
 * pass. The hidden rules are their own list, counted and reported, so a reader sees
 * what a lower level chose not to check rather than a green that quietly skipped it.
 */
final readonly class LevelGate
{
    /** Security and privacy run at any level — gated by severity, never by strictness. */
    private const array SEVERITY_GATED = [Category::Security, Category::Privacy];

    public function __construct(private Level $active) {}

    /**
     * The rules active at this level: those at or below it, plus the severity-gated
     * ones that ignore the level entirely.
     *
     * @return list<Rule>
     */
    public function active(RuleRegistry $registry): array
    {
        return $this->admitting($registry->executable());
    }

    /**
     * The same admission decision, applied to a list somebody else assembled.
     *
     * It exists so a caller can ask the level about rules the registry deliberately keeps OUT of
     * `executable()` — the deprecated ones. Announcing every deprecated rule in the package would be
     * noise; announcing the ones this level and these categories would otherwise have run is the
     * honest statement, and it needs exactly this decision applied to a different starting set.
     *
     * @param  list<Rule>  $rules
     * @return list<Rule>
     */
    public function admitting(array $rules): array
    {
        return array_values(array_filter($rules, $this->admits(...)));
    }

    /**
     * The rules this level hides — counted, never turned into a silent pass, so a
     * report can show what a lower level did not check.
     *
     * @return list<Rule>
     */
    public function hidden(RuleRegistry $registry): array
    {
        return array_values(array_filter($registry->executable(), fn (Rule $rule): bool => ! $this->admits($rule)));
    }

    private function admits(Rule $rule): bool
    {
        if ($this->active->includes($rule->level())) {
            return true;
        }

        return in_array($rule->category(), self::SEVERITY_GATED, true);
    }
}
