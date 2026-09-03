<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Pgls;

use JsonException;
use Pushery\SQLens\Exceptions\InvalidPglsRuleMap;

/**
 * Reads the bundled Postgres Language Server security catalog into typed rules.
 *
 * ## Why a shipped file rather than asking the binary
 *
 * The map answers "what do you lose without this tool" — a question the binary cannot answer,
 * because asking it would make the answer depend on whether it happens to be installed. A
 * machine without the tool would report a loss of zero, which is exactly backwards.
 *
 * ## Why the measured fields were measured
 *
 * The tool executes its whole catalog as one SQL statement in which each rule carries a
 * `-- meta:` header. The rule NAME, the SEVERITY and the help link came from those headers; the
 * summary beside them is this package's own sentence, because the tool's title and description are
 * its authors' prose and the NOTICE promises none of that is carried. Two other routes were tried and rejected: the project's website
 * (a list of what the documentation says, not of what the binary runs) and `strings` on the
 * binary itself, which returned two contradictory lists across two runs because adjacent
 * literals abut with no separator. Only the executed catalog is behavior.
 *
 * The catalog was read twice, against differently shaped databases — a plain one and one wearing
 * the Supabase shape the upstream linter was written for (an `auth.users` table, `anon` and
 * `authenticated` roles, an RLS table with a policy, a materialized view granted to `anon`).
 * Both runs executed the identical twelve rules, six of them SECURITY. That second run is the
 * control: without it, "the catalog is fixed" would be one observation wearing the clothes of a
 * property.
 *
 * Strict on load, like the other bundled artifacts: an unknown field is an error rather than an
 * ignored key, because a field nobody reads is a fact that silently does not apply while the
 * entry still looks complete.
 */
final readonly class PglsRuleMap
{
    /** The format this reader implements; an unknown version is an error, never a best effort. */
    public const int SCHEMA_VERSION = 1;

    /** The one place the path lives, so a relocation is a single edit. */
    public const string BUNDLED_FILE = 'resources/data/pgls-map.json';

    /** The fields an entry may carry. Anything else is rejected by name. */
    private const array FIELDS = ['rule', 'severity', 'summary', 'help_uri'];

    /** @param  array<string, PglsRule>  $rules  keyed by the tool's short rule name */
    private function __construct(
        /**
         * The tool version this map was measured against.
         *
         * It describes THAT build. The version window in {@see PglsTool} is drawn from it, and the
         * two move together — a map measured against one build and a window admitting another is
         * the state in which an adapter reads a report nobody has seen.
         */
        public string $measuredAgainst,
        /**
         * What the tool prefixes onto a rule name to form the category it emits, e.g.
         * `splinter/security/`. Stored once rather than repeated per entry: the composed string is
         * measured for one rule and inferred for the rest, and one inference in one place is
         * reviewable where six copies of it are not. The real-binary lane proves it for all six.
         */
        public string $categoryPrefix,
        public array $rules,
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

    public static function fromFile(string $path): self
    {
        $raw = @file_get_contents($path);

        if ($raw === false) {
            throw InvalidPglsRuleMap::unreadable($path);
        }

        $origin = basename($path);

        try {
            $decoded = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw InvalidPglsRuleMap::unparsable($origin, $e->getMessage());
        }

        if (! is_array($decoded)) {
            throw InvalidPglsRuleMap::malformedKey($origin, '', 'a JSON object');
        }

        if (($decoded['schema_version'] ?? null) !== self::SCHEMA_VERSION) {
            throw InvalidPglsRuleMap::unsupportedSchemaVersion($origin, $decoded['schema_version'] ?? null, self::SCHEMA_VERSION);
        }

        $measured = $decoded['measured_against'] ?? null;

        if (! is_string($measured) || $measured === '') {
            throw InvalidPglsRuleMap::malformedKey($origin, 'measured_against', 'the tool version this map was measured against');
        }

        $prefix = $decoded['category_prefix'] ?? null;

        if (! is_string($prefix) || $prefix === '') {
            throw InvalidPglsRuleMap::malformedKey($origin, 'category_prefix', 'the prefix the tool puts in front of a rule name');
        }

        $entries = $decoded['entries'] ?? null;

        if (! is_array($entries) || ! array_is_list($entries) || $entries === []) {
            throw InvalidPglsRuleMap::malformedKey($origin, 'entries', 'a non-empty list of entries');
        }

        return new self($measured, $prefix, self::readEntries($origin, $entries));
    }

    /**
     * Every rule the map describes, in the artifact's own order.
     *
     * @return list<string>
     */
    public function ruleNames(): array
    {
        return array_keys($this->rules);
    }

    public function for(string $rule): ?PglsRule
    {
        return $this->rules[$rule] ?? null;
    }

    /**
     * The rule behind a category string the tool emitted, or null when it is not one of ours.
     *
     * Null rather than an exception: a diagnostic from outside this catalog — a performance rule,
     * or a rule a later build added — is not a defect in the map. It is a finding this adapter has
     * nothing measured to say about, and the caller decides what to do with it.
     */
    public function forCategory(string $category): ?PglsRule
    {
        if (! str_starts_with($category, $this->categoryPrefix)) {
            return null;
        }

        return $this->for(substr($category, strlen($this->categoryPrefix)));
    }

    /**
     * @param  list<mixed>  $entries
     * @return array<string, PglsRule>
     */
    private static function readEntries(string $origin, array $entries): array
    {
        $rules = [];
        $previous = null;

        foreach ($entries as $position => $entry) {
            if (! is_array($entry) || ! is_string($entry['rule'] ?? null) || $entry['rule'] === '') {
                throw InvalidPglsRuleMap::malformedKey($origin, "entries.{$position}.rule", 'a non-empty rule name');
            }

            $rule = $entry['rule'];

            if (array_key_exists($rule, $rules)) {
                throw InvalidPglsRuleMap::duplicateRule($origin, $rule);
            }

            // Sorted, and checked rather than assumed. A map that drifted out of order would still
            // load perfectly and turn every future diff into noise, which is how a data artifact
            // stops being reviewable.
            //
            // Strictly less-than, and the duplicate check above is why: equality cannot arrive
            // here, because a repeated name was already rejected. Written `<=` it reads as if this
            // guard also caught duplicates — it would, if it ever saw one — and that half was
            // measured to be unreachable, so it is a branch nothing can turn red.
            if ($previous !== null && strcmp($rule, $previous) < 0) {
                throw InvalidPglsRuleMap::unsorted($origin, $rule);
            }

            $previous = $rule;
            $rules[$rule] = self::readEntry($origin, $rule, $entry);
        }

        return $rules;
    }

    /** @param  array<array-key, mixed>  $entry */
    private static function readEntry(string $origin, string $rule, array $entry): PglsRule
    {
        foreach (array_keys($entry) as $field) {
            if (! in_array($field, self::FIELDS, true)) {
                throw InvalidPglsRuleMap::unknownField($origin, $rule, (string) $field);
            }
        }

        $severityValue = $entry['severity'] ?? null;
        $severity = is_string($severityValue) ? PglsSeverity::tryFrom($severityValue) : null;

        if (! $severity instanceof PglsSeverity) {
            throw InvalidPglsRuleMap::unknownSeverity(
                $origin,
                $rule,
                is_scalar($severityValue) ? (string) $severityValue : strtoupper(get_debug_type($severityValue)),
                PglsSeverity::names(),
            );
        }

        $summary = $entry['summary'] ?? null;

        if (! is_string($summary) || $summary === '') {
            throw InvalidPglsRuleMap::malformedKey($origin, "{$rule}.summary", "a one-line explanation written for this package, never the tool's own wording");
        }

        $helpUri = $entry['help_uri'] ?? null;

        // https only, and required. A rule this package reports on somebody else's behalf has to be
        // followable to that somebody — a finding with no way out of it is where the reader stops.
        if (! is_string($helpUri) || ! str_starts_with($helpUri, 'https://')) {
            throw InvalidPglsRuleMap::malformedKey($origin, "{$rule}.help_uri", 'an https:// link the tool itself carries for this rule');
        }

        return new PglsRule($rule, $severity, $summary, $helpUri);
    }
}
