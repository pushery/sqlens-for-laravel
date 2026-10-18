<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

use Pushery\SQLens\Docs\DocumentationSite;
use Pushery\SQLens\Tools\Pgls\PglsFindingMapper;
use Pushery\SQLens\Tools\Pgls\PglsRule;
use Pushery\SQLens\Tools\Pgls\PglsRuleMap;
use Pushery\SQLens\Tools\Squawk\SquawkFindingMapper;
use Pushery\SQLens\Tools\Squawk\SquawkRuleMap;
use Pushery\SQLens\Tools\Squawk\SquawkRuleMapping;

/**
 * What this package says about a rule of an external tool, for a reader holding the id a finding reports.
 *
 * A Squawk or PGLS finding carries the tool's own rule name behind the tool's prefix, `SQUAWK.ban-char-field`
 * or `PGLS.extensionInPublic`, and the rule registry describes neither: those rules are the tool's. The cards
 * this package ships for the two tools do, with what a finding under the rule is filed as and where the tool
 * documents the rule. A rule neither card names gets no answer.
 */
final readonly class ToolRuleCards
{
    public function __construct(
        private ?SquawkRuleMap $squawk = null,
        private ?PglsRuleMap $pgls = null,
    ) {}

    /**
     * The card for one id, in the fields a finding under the rule carries, or null where neither card names it.
     *
     * @return array<string, mixed>|null
     */
    public function explain(string $ruleId): ?array
    {
        if (str_starts_with($ruleId, SquawkFindingMapper::ID_PREFIX)) {
            $mapping = ($this->squawk ?? SquawkRuleMap::bundled())->for(substr($ruleId, strlen(SquawkFindingMapper::ID_PREFIX)));

            return $mapping instanceof SquawkRuleMapping ? $this->squawkCard($ruleId, $mapping) : null;
        }

        if (str_starts_with($ruleId, PglsFindingMapper::ID_PREFIX)) {
            $rule = ($this->pgls ?? PglsRuleMap::bundled())->for(substr($ruleId, strlen(PglsFindingMapper::ID_PREFIX)));

            return $rule instanceof PglsRule ? $this->pglsCard($ruleId, $rule) : null;
        }

        return null;
    }

    /**
     * A Squawk rule as its card states it.
     *
     * A rule this package covers itself, or rules out for the servers it supports, reports nothing: its card
     * says so and names neither a category nor a level, because no finding is filed under it.
     *
     * @return array<string, mixed>
     */
    private function squawkCard(string $ruleId, SquawkRuleMapping $mapping): array
    {
        return [
            'id' => $ruleId,
            'tool' => 'squawk',
            'summary' => $mapping->rationale,
            'reported' => $mapping->surfaces(),
            'parity' => $mapping->parityStatus->value,
            'covered_by' => $mapping->sqlensRule,
            'category' => $mapping->category?->value,
            'level' => $mapping->level?->value,
            'severity' => $mapping->severity?->value,
            'min_version' => null,
            'max_version' => null,
            'downtime_class' => $mapping->downtimeClass?->value,
            'stability' => SquawkFindingMapper::STABILITY->value,
            'documentation_url' => $mapping->documentationUrl(),
            'source_url' => $mapping->sourceUrl,
        ];
    }

    /**
     * A PGLS rule as its card states it, filed the way every finding of the adapter is.
     *
     * @return array<string, mixed>
     */
    private function pglsCard(string $ruleId, PglsRule $rule): array
    {
        return [
            'id' => $ruleId,
            'tool' => 'pgls',
            'summary' => $rule->summary,
            'reported' => true,
            'category' => PglsFindingMapper::CATEGORY->value,
            'level' => PglsFindingMapper::LEVEL->value,
            'severity' => PglsFindingMapper::SEVERITIES[$rule->severity->value]->value,
            'min_version' => null,
            'max_version' => null,
            'downtime_class' => null,
            'stability' => PglsFindingMapper::STABILITY->value,
            'documentation_url' => DocumentationSite::page(PglsFindingMapper::DOCUMENTATION_PAGE),
            'source_url' => $rule->helpUri,
        ];
    }
}
