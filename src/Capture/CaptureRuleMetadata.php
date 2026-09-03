<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDeprecation;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Rules\VersionWindow;
use Pushery\SQLens\Severity\Severity;

/**
 * The published metadata a capture-layer finding producer carries — a pre-scan
 * detector or a level-0 capture rule. It is the same surface a Subject-based rule
 * carries, on the finding kinds the standard rule engine does not dispatch:
 * neither a pre-scan hit nor a capture-outcome judgment has a MigrationSql
 * subject to evaluate, so neither can be an engine rule, and yet everything users
 * and tooling consume about a rule applies to both unchanged — a stable id, a
 * category, a documentation page, a message prefix, a stability tier, a version
 * window. Leaving those off because "it is not an engine rule" would produce
 * findings that reports cannot group, baselines cannot address, and the generated
 * docs cannot list. So one metadata shape serves both families, audited by the
 * same invariants (RuleMetadataAudit::fieldViolations).
 *
 * Two fields are deliberately explicit rather than absent:
 *
 * - `versionWindow` is always unbounded and says so. The static pre-scan reads
 *   PHP, not a server, so no server version can change its answer. Omitting the
 *   field would leave a reader unable to tell "version-independent" from
 *   "nobody thought about versions".
 * - `downtimeClass` is null WITH a written rationale. A pre-scan hit describes no
 *   DDL, so it has no downtime behavior to classify — but a bare null is
 *   indistinguishable from a forgotten one, and the rationale is what makes the
 *   difference auditable.
 */
final readonly class CaptureRuleMetadata
{
    /**
     * @param  list<Suite>  $suites
     */
    public function __construct(
        public string $id,
        public Category $category,
        public Level $level,
        public ?Severity $severity,
        public StabilityTier $stability,
        public ?RuleDeprecation $deprecation,
        public VersionWindow $versionWindow,
        public ?DowntimeClass $downtimeClass,
        public string $downtimeClassRationale,
        public string $messagePrefix,
        public string $documentationUrl,
        public array $suites,
        public string $badExample,
        public string $goodExample,
    ) {}

    /**
     * A deterministic array projection with a fixed key order — what the
     * generated rule documentation and the agent rule export read.
     *
     * @return array{id: string, category: string, level: int, severity: string|null, stability: string, deprecated_since: string|null, min_version: string|null, max_version: string|null, downtime_class: string|null, downtime_class_rationale: string, message_prefix: string, documentation_url: string, suites: list<string>}
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'category' => $this->category->value,
            'level' => $this->level->value,
            'severity' => $this->severity?->value,
            'stability' => $this->stability->value,
            'deprecated_since' => $this->deprecation?->since,
            'min_version' => $this->versionWindow->minVersion?->toString(),
            'max_version' => $this->versionWindow->maxVersion?->toString(),
            'downtime_class' => $this->downtimeClass?->value,
            'downtime_class_rationale' => $this->downtimeClassRationale,
            'message_prefix' => $this->messagePrefix,
            'documentation_url' => $this->documentationUrl,
            'suites' => array_map(static fn (Suite $suite): string => $suite->value, $this->suites),
        ];
    }
}
