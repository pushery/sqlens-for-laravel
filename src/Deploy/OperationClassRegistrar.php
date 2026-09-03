<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Deploy\Contracts\DeclaresOperationClass;
use Pushery\SQLens\Findings\Finding;

/**
 * Which operation class a finding belongs to, resolved through the rule that produced it.
 *
 * A finding carries a `ruleId`, not a rule. So the lookup is built once from the rules that actually
 * ran, and each finding asks its own claimant — the same shape {@see DebtRegistrar::candidates()}
 * uses, deliberately, so there is one convention for "trace a finding back to its rule" rather than
 * two that can drift.
 *
 * ## Silence is an answer here
 *
 * A rule that does not implement {@see DeclaresOperationClass} produces findings with no class, and
 * those are returned as `null` rather than guessed at. That is the whole reason this is a lookup and
 * not a heuristic: a catalog rule judges a STATE and has no operation whose size could matter, and a
 * drop's danger is data loss rather than duration. Escalating either by row count would hang the
 * severity on an axis that says nothing about it — and it would do so plausibly, which is worse than
 * doing it obviously.
 */
final readonly class OperationClassRegistrar
{
    /**
     * The operation class of each finding, keyed the way the caller can use it.
     *
     * @param  list<Rule>  $rules  the rules that ran, so a finding can be traced back to the one
     *                             that claims it
     * @return array<string, string> rule id => operation class, for the rules that declare one
     */
    public static function byRuleId(array $rules): array
    {
        $declared = [];

        foreach ($rules as $rule) {
            if ($rule instanceof DeclaresOperationClass) {
                $declared[$rule->id()] = $rule->operationClass();
            }
        }

        // Sorted, because this map reaches a report through the escalation it drives, and two runs
        // over one database must not differ in the order anything is decided.
        ksort($declared);

        return $declared;
    }

    /**
     * The class for ONE finding, or null when its rule declares none.
     *
     * @param  array<string, string>  $declared  from {@see self::byRuleId()}
     */
    public static function for(Finding $finding, array $declared): ?string
    {
        return $declared[$finding->ruleId] ?? null;
    }
}
