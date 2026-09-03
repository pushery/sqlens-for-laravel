<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Exceptions\InvalidRuleEvidence;

/**
 * One piece of evidence: what establishes it, where it can be read, which version it
 * holds for, and what it says in our own words.
 *
 * `applies_to` is mandatory. Evidence without a version is the failure mode that looks
 * hardest to spot — a citation that is genuinely correct, for a release nobody is
 * running, supporting a rule that is wrong on the one they are.
 *
 * `note` is our wording, never the source's. The link is what is borrowed; a paraphrase
 * close enough to be a copy is a copy, and the register would then carry someone else's
 * text under this package's license.
 */
final readonly class RuleEvidenceEntry
{
    /** The kinds of evidence a rule may cite. A free-text kind is not one. */
    public const array TYPES = ['doc', 'incident'];

    private function __construct(
        public string $type,
        public string $url,
        public string $appliesTo,
        public string $note,
    ) {}

    /** @param  array<string, mixed>  $data */
    public static function fromArray(array $data, string $origin, string $ruleId, int $index): self
    {
        $where = "entries.{$ruleId}[{$index}]";

        $type = self::string($data, 'type', $origin, $where);

        if (! in_array($type, self::TYPES, true)) {
            throw InvalidRuleEvidence::malformed($origin, $where.'.type', 'one of '.implode(', ', self::TYPES));
        }

        $url = self::string($data, 'url', $origin, $where);

        // A citation nobody can follow is not evidence. The shape is checked here; that
        // the page still says what we claim is a human's job at review time.
        if (! str_starts_with($url, 'https://')) {
            throw InvalidRuleEvidence::malformed($origin, $where.'.url', 'an https:// link');
        }

        return new self(
            type: $type,
            url: $url,
            appliesTo: self::string($data, 'applies_to', $origin, $where),
            note: self::string($data, 'note', $origin, $where),
        );
    }

    /** @param  array<string, mixed>  $data */
    private static function string(array $data, string $key, string $origin, string $where): string
    {
        $value = $data[$key] ?? null;

        if (! is_string($value) || trim($value) === '') {
            throw InvalidRuleEvidence::malformed($origin, $where.'.'.$key, 'a non-empty string');
        }

        return $value;
    }
}
