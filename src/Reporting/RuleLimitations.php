<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Generation\ShippedRuleMetadata;
use Pushery\SQLens\Generation\UnresolvableRuleCatalog;

/**
 * What each rule deliberately does not answer, read from the shipped rule catalog by rule id.
 *
 * The catalog carries `limitations` for every rule that declares them, and `explain_rule` answers with the same
 * rows. Reading them here keeps one description of a rule's limits: the JSON report, the agent report and the
 * console footnote say what the catalog says.
 *
 * Their point is the reading of a result. A rule that found nothing found nothing within these limits, and a
 * report that leaves them out turns "found nothing here" into "found nothing".
 *
 * The lookup is by exact id. An id the catalog holds no row for answers null, and so does a member of a family
 * row, which is why no family row may declare limitations without this lookup learning about families first. A
 * catalog that cannot be read is refused with {@see UnresolvableRuleCatalog}, which the catalog reader throws: read
 * as empty, it would say that no rule has a limit, which is the wrong answer this exists to prevent.
 */
final readonly class RuleLimitations
{
    /** @param  array<string, non-empty-list<string>>  $byRule */
    private function __construct(private array $byRule) {}

    /**
     * The limitations the catalog that ships with this package declares.
     *
     * @throws UnresolvableRuleCatalog
     */
    public static function shipped(): self
    {
        $byRule = [];

        foreach (ShippedRuleMetadata::shipped() as $id => $row) {
            $limitations = [];

            foreach (is_array($row['limitations'] ?? null) ? $row['limitations'] : [] as $limitation) {
                if (is_string($limitation) && $limitation !== '') {
                    $limitations[] = $limitation;
                }
            }

            if ($limitations !== []) {
                $byRule[$id] = $limitations;
            }
        }

        return new self($byRule);
    }

    /**
     * What one rule does not answer, or null where it declares nothing.
     *
     * @return non-empty-list<string>|null
     */
    public function of(string $ruleId): ?array
    {
        return $this->byRule[$ruleId] ?? null;
    }

    /**
     * Each rule among the findings that declares limitations, once, ordered by rule id.
     *
     * @param  list<Finding>  $findings
     * @return array<string, non-empty-list<string>>
     */
    public function forFindings(array $findings): array
    {
        $byRule = [];

        foreach ($findings as $finding) {
            $limitations = $this->of($finding->ruleId);

            if ($limitations !== null) {
                $byRule[$finding->ruleId] = $limitations;
            }
        }

        ksort($byRule, SORT_STRING);

        return $byRule;
    }
}
