<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use JsonException;
use Pushery\SQLens\Exceptions\InvalidRuleExample;

/**
 * The bad/good examples for the rules, read from the bundled register.
 *
 * A finding names a rule; the rule's example is what turns that name into something a
 * user can act on — "here is the migration that trips it, here is the one that does not".
 * The examples live as data rather than as prose in docblocks, exactly like the evidence
 * register, so they can be reviewed as a list and a diff shows which example moved. The
 * documentation generator reads this register; it does not invent examples.
 *
 * One example per rule: a single bad and a single good, not a list — the example teaches
 * the shape, the fixtures cover the variants. A malformed register is an error rather
 * than an empty result, so a typo in a rule id cannot make that rule silently
 * example-free while the completeness check passes over the gap.
 */
final readonly class RuleExamples
{
    /** The register format this reader implements; an unknown version is an error. */
    public const int SCHEMA_VERSION = 1;

    /** @param  array<string, RuleExampleEntry>  $entries  keyed by rule id */
    private function __construct(public array $entries) {}

    public static function bundled(): self
    {
        return self::fromFile(dirname(__DIR__, 2).'/resources/data/rule-examples.json');
    }

    public static function fromFile(string $path): self
    {
        $raw = @file_get_contents($path);

        if ($raw === false) {
            throw InvalidRuleExample::unreadable($path);
        }

        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw InvalidRuleExample::unparsable($path, $exception->getMessage());
        }

        return self::fromArray($decoded, $path);
    }

    /** @param  array<string, mixed>  $data */
    public static function fromArray(array $data, string $origin): self
    {
        $version = $data['schema_version'] ?? null;

        if ($version !== self::SCHEMA_VERSION) {
            throw InvalidRuleExample::unsupportedSchemaVersion($origin, $version, self::SCHEMA_VERSION);
        }

        $raw = $data['entries'] ?? null;

        if (! is_array($raw)) {
            throw InvalidRuleExample::malformed($origin, 'entries', 'an object keyed by rule id');
        }

        $entries = [];

        foreach ($raw as $ruleId => $entry) {
            if (! is_string($ruleId) || $ruleId === '') {
                throw InvalidRuleExample::malformed($origin, 'entries', 'rule ids as non-empty strings');
            }

            if (! is_array($entry)) {
                throw InvalidRuleExample::malformed($origin, "entries.{$ruleId}", 'an example object');
            }

            /** @var array<string, mixed> $entry */
            $entries[$ruleId] = RuleExampleEntry::fromArray($entry, $origin, $ruleId);
        }

        // Sorted here rather than trusted from the file: the register is reviewed as a
        // diff, and an entry that moved because someone appended rather than inserted is
        // noise a reviewer learns to skip past.
        ksort($entries);

        return new self($entries);
    }

    public function for(string $ruleId): ?RuleExampleEntry
    {
        return $this->entries[$ruleId] ?? null;
    }

    public function has(string $ruleId): bool
    {
        return isset($this->entries[$ruleId]);
    }
}
