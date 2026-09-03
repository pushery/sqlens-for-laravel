<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Squawk;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Severity\Severity;

/**
 * One tool rule, and everything SQLens decided about it.
 *
 * The metadata is OURS, not the tool's. A tool's severity words, levels and categories belong to
 * its own vocabulary; carrying them through would put two scales in one report and leave the
 * reader to work out which one a number came from.
 */
final readonly class SquawkRuleMapping
{
    public function __construct(
        /** The tool's own rule name, e.g. `require-concurrent-index-creation`. */
        public string $rule,
        /** The SQLens rule that covers the same ground, or null when none does. */
        public ?string $sqlensRule,
        /**
         * Our category and level, TYPED — or null for a rule whose findings never surface.
         *
         * Resolved while the artifact is read rather than every time a finding is mapped. A
         * category string the enum does not know would otherwise fall back to something at
         * runtime, and a fallback is how an artifact with a typo produces findings under a
         * category nobody chose.
         */
        public ?Category $category,
        public ?Level $level,
        /** Our security severity — null for everything that is not a security or privacy finding. */
        public ?Severity $severity,
        /** `online`, `blocking`, `rewrite`, or null when it genuinely is not derivable. */
        public ?DowntimeClass $downtimeClass,
        /**
         * The key that says "this is the same problem as that".
         *
         * Shared between the tool's rule and the SQLens rule that covers it, and between tool
         * rules that describe one hazard from different angles — which is what lets de-duplication
         * drop a repeat without needing to compare message text.
         */
        public ?string $dedupeGroup,
        public SquawkParityStatus $parityStatus,
        /**
         * Whether `--exclude` accepts this name.
         *
         * Not a formality: `syntax-error` is emitted as a rule name and REJECTED as an exclude
         * value (both measured). Anything that builds an exclude list from this map would produce
         * an invocation the tool refuses outright.
         */
        public bool $excludable,
        /** Why this decision — written here, never carried over from the tool's own docs. */
        public string $rationale,
        public string $sourceUrl,
    ) {}

    /** Whether a finding under this rule reaches the report at all. */
    public function surfaces(): bool
    {
        return $this->parityStatus->surfaces();
    }
}
