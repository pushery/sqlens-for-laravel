<?php

declare(strict_types=1);

namespace Pushery\SQLens\Config;

/**
 * One rule id somebody wrote down somewhere, together with exactly where they
 * wrote it. The location is not decoration: a suppression that names an id no
 * rule answers to is only fixable if the message says which of the three places
 * it came from.
 */
final readonly class RuleIdReference
{
    /** @param  string  $location  the concrete spot: a config path, a baseline entry key, a migration class */
    public function __construct(
        public string $ruleId,
        public RuleIdOrigin $origin,
        public string $location,
    ) {}

    public static function inConfigIgnore(string $ruleId, int $index): self
    {
        return new self($ruleId, RuleIdOrigin::ConfigIgnore, 'sqlens.ignore.'.$index.'.rule');
    }

    /**
     * A rule id written into the audit ignore list, at the form and position it came from.
     *
     * The position is part of the location because two entries can be byte-identical, and telling
     * somebody "the id at objects.3 is unknown" is what lets them find and fix the line. A message
     * that named only the id would send them searching.
     */
    public static function inAuditIgnore(string $ruleId, string $form, int $index): self
    {
        return new self($ruleId, RuleIdOrigin::AuditIgnore, 'sqlens.audit.ignore.'.$form.'.'.$index);
    }

    public static function inBaseline(string $ruleId, string $entryKey): self
    {
        return new self($ruleId, RuleIdOrigin::Baseline, 'entry '.$entryKey);
    }

    public static function inAnnotation(string $ruleId, string $migrationClass): self
    {
        return new self($ruleId, RuleIdOrigin::Annotation, $migrationClass);
    }

    /** How this reference reads inside a message: origin, then the exact spot. */
    public function describe(): string
    {
        return $this->origin->label().' at '.$this->location;
    }
}
