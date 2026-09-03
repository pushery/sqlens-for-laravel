<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use JsonException;
use Pushery\SQLens\Exceptions\InvalidRuleEvidence;

/**
 * The evidence behind the safety rules, read from the bundled register.
 *
 * A safety rule tells someone their migration is dangerous. That claim has to be
 * answerable — "because the documentation says this operation takes that lock" — or it
 * is an opinion with a rule id. The register is where each rule's answer lives, as data
 * rather than as prose scattered through docblocks, so it can be reviewed as a list and
 * a diff shows exactly which claim moved.
 *
 * Every entry names the version it applies to. That is not bookkeeping: PostgreSQL has
 * changed which operations rewrite a table more than once, and an anchor from an older
 * major would justify a rule that is simply wrong on this baseline — confidently, and
 * with a citation.
 *
 * A malformed register is an error rather than an empty result. Read leniently, a typo
 * in a rule id would make that rule silently evidence-free, and the completeness check
 * that is supposed to catch exactly that would pass.
 */
final readonly class RuleEvidence
{
    /** The register format this reader implements; an unknown version is an error. */
    public const int SCHEMA_VERSION = 1;

    /** @param  array<string, list<RuleEvidenceEntry>>  $entries  keyed by rule id */
    private function __construct(public array $entries) {}

    public static function bundled(): self
    {
        return self::fromFile(dirname(__DIR__, 2).'/resources/data/rule-evidence.json');
    }

    public static function fromFile(string $path): self
    {
        $raw = @file_get_contents($path);

        if ($raw === false) {
            throw InvalidRuleEvidence::unreadable($path);
        }

        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw InvalidRuleEvidence::unparsable($path, $exception->getMessage());
        }

        return self::fromArray($decoded, $path);
    }

    /** @param  array<string, mixed>  $data */
    public static function fromArray(array $data, string $origin): self
    {
        $version = $data['schema_version'] ?? null;

        if ($version !== self::SCHEMA_VERSION) {
            throw InvalidRuleEvidence::unsupportedSchemaVersion($origin, $version, self::SCHEMA_VERSION);
        }

        $raw = $data['entries'] ?? null;

        if (! is_array($raw)) {
            throw InvalidRuleEvidence::malformed($origin, 'entries', 'an object keyed by rule id');
        }

        $entries = [];

        foreach ($raw as $ruleId => $list) {
            if (! is_string($ruleId) || $ruleId === '') {
                throw InvalidRuleEvidence::malformed($origin, 'entries', 'rule ids as non-empty strings');
            }

            if (! is_array($list) || $list === []) {
                throw InvalidRuleEvidence::malformed($origin, "entries.{$ruleId}", 'at least one evidence entry');
            }

            $parsed = [];

            foreach (array_values($list) as $index => $entry) {
                if (! is_array($entry)) {
                    throw InvalidRuleEvidence::malformed($origin, "entries.{$ruleId}[{$index}]", 'an object');
                }

                /** @var array<string, mixed> $entry */
                $parsed[] = RuleEvidenceEntry::fromArray($entry, $origin, $ruleId, $index);
            }

            $entries[$ruleId] = $parsed;
        }

        // Sorted here rather than trusted from the file: the register is reviewed as a
        // diff, and an entry that moved because someone appended rather than inserted
        // is noise a reviewer learns to skip past.
        ksort($entries);

        return new self($entries);
    }

    /** @return list<RuleEvidenceEntry> */
    public function for(string $ruleId): array
    {
        return $this->entries[$ruleId] ?? [];
    }

    public function has(string $ruleId): bool
    {
        return ($this->entries[$ruleId] ?? []) !== [];
    }
}
