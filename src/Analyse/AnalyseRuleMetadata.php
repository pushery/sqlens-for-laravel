<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Severity\Severity;

/**
 * The published metadata an analyse-suite rule carries — the fourth finding family.
 *
 * ## Why a fourth shape, and why it is a small one
 *
 * The registry export already unions three families, because a producer that the export cannot see
 * is a set of ids with no documentation page and nothing to notice the gap. An analyse rule is a
 * PHPStan rule: it judges a CALL SITE in PHP source rather than a `Subject`, so it cannot implement
 * the engine's `Rule` contract — and `CaptureRuleMetadata` names the capture layer and carries the
 * example pair that layer's docs generator needs. Reusing either would have been a name that lies.
 *
 * So this holds exactly the fields the export row needs and nothing else. If a fifth family appears
 * wanting the same shape, the three near-identical records are worth unifying THEN — one shared
 * record invented for two callers usually acquires a field for each of them.
 *
 * ## `limitations` is not optional, and that is the point of this record existing
 *
 * The rule it describes ships a hard honesty boundary: it never reads the query text, and it is not
 * taint analysis. That boundary lived only in the PHPStan tip — a string a report cannot carry into
 * SARIF, into the GitHub reporter, or into an agent artifact. Here it is a field, so every consumer
 * that shows a finding can show what the finding does not claim.
 */
final readonly class AnalyseRuleMetadata
{
    /**
     * @param  list<Suite>  $suites
     * @param  non-empty-list<string>  $limitations  what this rule deliberately does not answer
     */
    public function __construct(
        public string $id,
        public Category $category,
        public Level $level,
        public Severity $severity,
        public StabilityTier $stability,
        public string $messagePrefix,
        public array $suites,
        public array $limitations,
        /**
         * The identifier PHPStan reports this rule under — the SECOND vocabulary a consumer meets.
         *
         * Every other finding family reports under its rule id, so there is nothing to bridge. This
         * one does not: PHPStan owns the identifier namespace of its own output, and a machine
         * reading `--error-format=json` gets that string and never the rule id. Carrying both is
         * what lets such a consumer reach the severity, category and level this catalog holds.
         */
        public ?string $reportedIdentifier = null,
    ) {}

    /**
     * The page this rule's id resolves to, derived exactly like every other id's.
     *
     * Derived rather than stored: an address written by hand is one somebody can typo into a
     * 404 that no test notices, and the whole reason the package has one derivation is that a
     * finding's link has to work without anybody checking it per rule.
     */
    public function documentationUrl(): string
    {
        return RuleDocumentationUrl::for($this->id);
    }
}
