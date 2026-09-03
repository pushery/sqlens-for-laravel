<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Squawk;

use JsonException;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Exceptions\InvalidSquawkRuleMap;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Severity\Severity;

/**
 * Reads the bundled Squawk rule map into typed mappings.
 *
 * The map is the single source of truth for what SQLens does about each of the tool's rules:
 * the finding mapper reads it, de-duplication reads it, the parity list is generated from it,
 * and `sqlens:doctor` reports what the tool would add from it. The BINARY is never that source
 * — it cannot say what SQLens covers, and asking it would make the answer depend on whether it
 * happens to be installed.
 *
 * Strict on load, in the same way the other bundled artifacts are: an unknown field is an
 * error rather than an ignored key, because a field nobody reads is a fact that silently does
 * not apply, and the entry still looks complete. Likewise a mapping onto a SQLens rule id that
 * does not exist — the map would be pointing at nothing, and the finding it described would
 * quietly stop de-duplicating.
 */
final readonly class SquawkRuleMap
{
    /** The format this reader implements; an unknown version is an error, never a best effort. */
    public const int SCHEMA_VERSION = 1;

    /** The one place the path lives, so a relocation is a single edit. */
    public const string BUNDLED_FILE = 'resources/data/squawk-map.json';

    /** The fields an entry may carry. Anything else is rejected by name. */
    private const array FIELDS = [
        'rule', 'sqlens_rule', 'category', 'level', 'severity', 'downtime_class',
        'dedupe_group', 'parity_status', 'excludable', 'rationale', 'source_url',
    ];

    /** @param  array<string, SquawkRuleMapping>  $mappings  keyed by the tool's rule name */
    private function __construct(
        /** The tool version this map was measured against — the map describes that build, not the website. */
        public string $measuredAgainst,
        public array $mappings,
    ) {}

    /**
     * The bundled map, parsed once per process.
     *
     * Only this accessor memoizes; {@see self::fromFile()} always reads, so a test pointing at
     * another file can never be handed the bundled copy.
     */
    public static function bundled(): self
    {
        static $bundled = null;

        if (! $bundled instanceof self) {
            $bundled = self::fromFile(dirname(__DIR__, 3).'/'.self::BUNDLED_FILE);
        }

        return $bundled;
    }

    /**
     * @param  list<string>  $knownSqlensRules  the rule ids a mapping may point at. Passed in
     *                                          rather than read here: the registry is the other
     *                                          artifact's business, and a loader that read both
     *                                          would tie a change in one to a failure in the other.
     */
    public static function fromFile(string $path, array $knownSqlensRules = []): self
    {
        $raw = @file_get_contents($path);

        if ($raw === false) {
            throw InvalidSquawkRuleMap::unreadable($path);
        }

        $origin = basename($path);

        try {
            $decoded = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw InvalidSquawkRuleMap::unparsable($origin, $e->getMessage());
        }

        if (! is_array($decoded)) {
            throw InvalidSquawkRuleMap::malformedKey($origin, '', 'a JSON object');
        }

        if (($decoded['schema_version'] ?? null) !== self::SCHEMA_VERSION) {
            throw InvalidSquawkRuleMap::unsupportedSchemaVersion($origin, $decoded['schema_version'] ?? null, self::SCHEMA_VERSION);
        }

        $measured = $decoded['measured_against'] ?? null;

        if (! is_string($measured) || $measured === '') {
            throw InvalidSquawkRuleMap::malformedKey($origin, 'measured_against', 'the tool version this map was measured against');
        }

        $entries = $decoded['entries'] ?? null;

        if (! is_array($entries) || ! array_is_list($entries)) {
            throw InvalidSquawkRuleMap::malformedKey($origin, 'entries', 'a list of entries');
        }

        return new self($measured, self::readEntries($origin, $entries, $knownSqlensRules));
    }

    /**
     * Every rule the map describes, in the artifact's own order.
     *
     * @return list<string>
     */
    public function rules(): array
    {
        return array_keys($this->mappings);
    }

    public function for(string $rule): ?SquawkRuleMapping
    {
        return $this->mappings[$rule] ?? null;
    }

    /**
     * @param  list<mixed>  $entries
     * @param  list<string>  $knownSqlensRules
     * @return array<string, SquawkRuleMapping>
     */
    private static function readEntries(string $origin, array $entries, array $knownSqlensRules): array
    {
        $mappings = [];
        $previous = null;

        foreach ($entries as $position => $entry) {
            if (! is_array($entry) || ! is_string($entry['rule'] ?? null) || $entry['rule'] === '') {
                throw InvalidSquawkRuleMap::malformedKey($origin, "entries.{$position}.rule", 'a non-empty rule name');
            }

            $rule = $entry['rule'];

            if (array_key_exists($rule, $mappings)) {
                throw InvalidSquawkRuleMap::duplicateRule($origin, $rule);
            }

            // Sorted, and checked rather than assumed. A map that drifted out of order would still
            // load perfectly and turn every future diff into noise, which is how a data artifact
            // stops being reviewable.
            if ($previous !== null && strcmp($rule, $previous) <= 0) {
                throw InvalidSquawkRuleMap::unsorted($origin, $rule);
            }

            $previous = $rule;
            $mappings[$rule] = self::readEntry($origin, $rule, $entry, $knownSqlensRules);
        }

        return $mappings;
    }

    /**
     * @param  array<array-key, mixed>  $entry
     * @param  list<string>  $knownSqlensRules
     */
    private static function readEntry(string $origin, string $rule, array $entry, array $knownSqlensRules): SquawkRuleMapping
    {
        foreach (array_keys($entry) as $field) {
            if (! in_array($field, self::FIELDS, true)) {
                throw InvalidSquawkRuleMap::unknownField($origin, $rule, (string) $field);
            }
        }

        $status = SquawkParityStatus::tryFrom(is_string($entry['parity_status'] ?? null) ? $entry['parity_status'] : '');

        if (! $status instanceof SquawkParityStatus) {
            throw InvalidSquawkRuleMap::unknownParityStatus(
                $origin,
                $rule,
                is_scalar($entry['parity_status'] ?? null) ? (string) $entry['parity_status'] : strtoupper(get_debug_type($entry['parity_status'] ?? null)),
                implode(', ', SquawkParityStatus::names()),
            );
        }

        $sqlensRule = $entry['sqlens_rule'] ?? null;

        if ($sqlensRule !== null && (! is_string($sqlensRule) || ($knownSqlensRules !== [] && ! in_array($sqlensRule, $knownSqlensRules, true)))) {
            throw InvalidSquawkRuleMap::unknownSqlensRule($origin, $rule, is_scalar($sqlensRule) ? (string) $sqlensRule : strtoupper(get_debug_type($sqlensRule)));
        }

        $rationale = $entry['rationale'] ?? null;

        if (! is_string($rationale) || $rationale === '') {
            throw InvalidSquawkRuleMap::malformedKey($origin, "{$rule}.rationale", 'a non-empty explanation written for this map');
        }

        $sourceUrl = $entry['source_url'] ?? null;

        if (! is_string($sourceUrl) || ! str_starts_with($sourceUrl, 'https://')) {
            throw InvalidSquawkRuleMap::malformedKey($origin, "{$rule}.source_url", 'an https:// link to the rule upstream');
        }

        // A surfacing rule needs somewhere to surface. Without this pairing the map could carry an
        // entry that says "report this" and nothing saying at which level or under which category,
        // which reads as complete and produces a finding nobody can gate on.
        $category = $entry['category'] ?? null;
        $level = $entry['level'] ?? null;

        $category = is_string($category) ? Category::tryFrom($category) : null;
        $level = is_int($level) ? Level::tryFrom($level) : null;

        if ($status->surfaces() && (! $category instanceof Category || ! $level instanceof Level)) {
            throw InvalidSquawkRuleMap::malformedKey($origin, "{$rule}.category/level", 'a known category and a level between 0 and 9, because findings under this parity status are reported');
        }

        $downtime = $entry['downtime_class'] ?? null;
        $downtimeClass = is_string($downtime) ? DowntimeClass::tryFrom($downtime) : null;

        if (is_string($downtime) && ! $downtimeClass instanceof DowntimeClass) {
            throw InvalidSquawkRuleMap::malformedKey($origin, "{$rule}.downtime_class", 'online, blocking, rewrite, or null when it genuinely is not derivable');
        }

        $severityValue = $entry['severity'] ?? null;
        $severity = is_string($severityValue) ? Severity::tryFrom($severityValue) : null;

        if (is_string($severityValue) && ! $severity instanceof Severity) {
            throw InvalidSquawkRuleMap::malformedKey($origin, "{$rule}.severity", 'a known severity, or null for anything that is not a security or privacy finding');
        }

        if (! is_bool($entry['excludable'] ?? null)) {
            throw InvalidSquawkRuleMap::malformedKey($origin, "{$rule}.excludable", 'a boolean saying whether --exclude accepts this name');
        }

        return new SquawkRuleMapping(
            rule: $rule,
            sqlensRule: is_string($sqlensRule) ? $sqlensRule : null,
            category: $category,
            level: $level,
            severity: $severity,
            downtimeClass: $downtimeClass,
            dedupeGroup: is_string($entry['dedupe_group'] ?? null) ? $entry['dedupe_group'] : null,
            parityStatus: $status,
            excludable: $entry['excludable'],
            rationale: $rationale,
            sourceUrl: $sourceUrl,
        );
    }
}
