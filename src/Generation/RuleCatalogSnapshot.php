<?php

declare(strict_types=1);

namespace Pushery\SQLens\Generation;

use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Severity\Severity;

/**
 * The active rule set, frozen: one deterministically sorted document that every agent output
 * reads from and none of them re-derives.
 *
 * ## Why one source and not three
 *
 * The renderers downstream write into three different files for three different tools. If each
 * asked the registry its own question, three answers would drift — and the drift would show up as
 * an agent being told a rule applies that its pipeline does not run, which is the exact failure
 * the whole export chain exists to prevent. They all get this object, and the architecture test
 * says so.
 *
 * ## Where the metadata comes from
 *
 * From `resources/data/rule-registry.json`, the artifact a test already holds byte-identical to
 * the code. Not from a second walk over the rule objects: a rule's category, level, severity,
 * downtime class and documentation address have exactly one description in this package, and a
 * second one would be a second thing to keep in step.
 *
 * The join is CHECKED rather than trusted. An active rule the artifact carries no row for is a
 * named refusal, because the silent alternative — omit it — is a rule that really runs and that
 * nobody was warned about. That is the direction a stale build artifact fails in, and it is the
 * quiet one.
 *
 * ## Determinism
 *
 * Rows are sorted by id with a byte comparison, never a collation: a locale-aware sort puts a
 * developer's Mac and CI in disagreement about a file both of them generate, and the diff of a
 * real change becomes unreadable. Nothing here reads a clock, an environment variable or a path.
 * Two runs over one state produce identical bytes and an identical hash.
 */
final readonly class RuleCatalogSnapshot
{
    /**
     * The document's shape version. A reader that understands 1 may refuse a 2 it does not know
     * rather than misreading it — the same promise the rule registry makes.
     */
    public const int SCHEMA_VERSION = 1;

    /**
     * @param  list<array<array-key, mixed>>  $entries  sorted by id, each row already marked
     * @param  list<string>  $versionDependentIds  the marked subset, kept as ids rather than re-read
     *                                             out of the rows: a row is `array<string, mixed>`
     *                                             once it carries the shipped metadata, so pulling
     *                                             an id back out of one would need a cast or a
     *                                             defensive branch nothing could ever reach
     */
    private function __construct(
        public array $entries,
        public RuleCatalogContext $context,
        public array $versionDependentIds,
    ) {}

    /**
     * Build from the resolver's two sets.
     *
     * The two arrive separately because they mean different things and the mark is not
     * recoverable afterwards: both lists hold rules that apply, but the second could not be
     * PLACED against a server version. Merging them first and marking later would need this class
     * to re-derive which was which, from the very window evaluation the version gate just did.
     *
     * @param  list<Rule>  $applies
     * @param  list<Rule>  $versionDependent
     * @param  array<string, array<array-key, mixed>>  $metadata  the shipped description of each rule
     *
     * @throws UnresolvableRuleCatalog
     */
    public static function of(array $applies, array $versionDependent, RuleCatalogContext $context, array $metadata): self
    {
        $floor = $context->minSeverity === null ? null : Severity::tryFrom($context->minSeverity);

        /** @var array<string, array<string, mixed>> $rows */
        $rows = [];

        $dependentIds = [];

        foreach ([[$applies, false], [$versionDependent, true]] as [$rules, $dependent]) {
            foreach ($rules as $rule) {
                $rows[$rule->id()] = self::row($rule, $metadata, $dependent, $floor);

                if ($dependent) {
                    $dependentIds[] = $rule->id();
                }
            }
        }

        // Byte comparison, deliberately: `ksort` with SORT_STRING never consults a locale, so the
        // order is the same on every machine that will ever regenerate this file.
        ksort($rows, SORT_STRING);
        sort($dependentIds, SORT_STRING);

        return new self(array_values($rows), $context, $dependentIds);
    }

    /**
     * The whole document, hash last.
     *
     * Last because the hash is OVER the rest: it is computed from this same array with the key
     * absent, so a reader can recompute it without knowing an exclusion rule, and a renderer's
     * `--check` compares one string instead of two documents.
     *
     * @return array{schema_version: int, context: array<string, mixed>, version_note: string|null, counts: array{total: int, version_dependent: int, ignored: int}, entries: list<array<array-key, mixed>>, hash: string}
     */
    public function toArray(): array
    {
        $payload = $this->payload();

        return [...$payload, 'hash' => $this->hash()];
    }

    /**
     * A stable fingerprint of everything this snapshot says, context included.
     *
     * The context is inside the hash rather than beside it, because two catalogs can hold the same
     * rules for different reasons — a level-4 run on a pinned PostgreSQL 18 and a level-4 run with
     * no pin at all differ in what they ESTABLISHED, not only in what they listed. A marker line
     * that could not tell them apart would report a generated file as current after the world
     * moved underneath it.
     */
    public function hash(): string
    {
        return hash('sha256', json_encode($this->payload(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }

    /**
     * Everything except the hash — the bytes the hash is taken over.
     *
     * @return array{schema_version: int, context: array<string, mixed>, version_note: string|null, counts: array{total: int, version_dependent: int, ignored: int}, entries: list<array<array-key, mixed>>}
     */
    private function payload(): array
    {
        return [
            'schema_version' => self::SCHEMA_VERSION,
            'context' => $this->context->toArray(),
            'version_note' => $this->context->versionNote(),
            'counts' => [
                'total' => count($this->entries),
                'version_dependent' => count($this->versionDependentIds),
                'ignored' => count($this->context->ignoredRuleIds),
            ],
            'entries' => $this->entries,
        ];
    }

    /**
     * One row: the shipped metadata, plus the two facts only this layer knows.
     *
     * `blocking` is here because it is the field that changes what somebody DOES. A security rule
     * below the project's floor still reports and still appears — it just does not stop a deploy,
     * and an agent told only that the rule exists cannot tell the two apart. The comparison is
     * asked of {@see Severity::isAtLeast()} rather than re-ranked here; there is one ordering of
     * severities in this package and this is not a second one.
     *
     * @param  array<string, array<array-key, mixed>>  $metadata
     * @return array<array-key, mixed>
     *
     * @throws UnresolvableRuleCatalog
     */
    private static function row(Rule $rule, array $metadata, bool $versionDependent, ?Severity $floor): array
    {
        $id = $rule->id();
        $row = $metadata[$id] ?? throw UnresolvableRuleCatalog::missingMetadata($id);

        if (! is_string($row['documentation_url'] ?? null) || $row['documentation_url'] === '') {
            throw UnresolvableRuleCatalog::undocumentedRule($id);
        }

        $severity = is_string($row['severity'] ?? null) ? Severity::tryFrom($row['severity']) : null;

        // Assigned rather than spread. A spread renumbers integer keys, and — worse — a spread
        // that put the artifact's row LAST would let a future `blocking` column in the registry
        // silently overwrite the one computed here. Assignment always wins, which is the only
        // correct direction: these two fields are this layer's answer, not the artifact's.
        $row['version_dependent'] = $versionDependent;

        // A rule with no severity is not measured on that axis at all, so it is not "below the
        // floor" — it is judged by the level gate, and it blocks there. Reporting false would read
        // as "this one is advisory", which is the opposite of what a level-gated safety rule does.
        $row['blocking'] = $severity instanceof Severity
            ? ($floor instanceof Severity && $severity->isAtLeast($floor))
            : true;

        return $row;
    }
}
