<?php

declare(strict_types=1);

namespace Pushery\SQLens\Api;

use Pushery\SQLens\Console\ExitCode;
use Pushery\SQLens\Exceptions\MalformedRuleRegistry;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Reporting\Baseline\BaselineSchema;
use Pushery\SQLens\Reporting\Json\JsonEnvelope;

/**
 * The promised surface, as data a machine can diff.
 *
 * ## Why this is a PROJECTION and not a second derivation
 *
 * `resources/data/rule-registry.json` already carries, for all 196 entries, every per-rule field
 * this snapshot needs: category, level, severity, stability, message prefix, documentation url,
 * `deprecated_since`, `replaced_by`. Deriving them a second time from the rule objects would create
 * two answers to "what is this rule's severity" — and they would agree until the day one generator
 * learned a new rule source and the other did not.
 *
 * So this reads the registry and PROJECTS it. Nothing here recomputes a rule fact.
 *
 * ## And why the projection is narrower than the registry, which is the whole point
 *
 * The registry is the DOCUMENTATION catalog. It carries `slug`, `suites`, `documentation_state`,
 * `confidence`, `source` — all useful, none of them promised. A page can be rewritten, a rule can
 * join a second suite, a slug can change: none of that costs a major release.
 *
 * This file holds what a major release IS. The difference between the two lists is the contract,
 * and a snapshot that simply copied the registry would make every documentation edit look like a
 * breaking change — which is how a breaking-change gate gets switched off in its first month.
 *
 * ## Non-rule facts
 *
 * Four things are promised that no rule carries: the exit-code table, the baseline schema version,
 * the report schema version, and the remediation schema — the last one with its STABILITY beside
 * its version, because it ships as `preview` and its whole special case is that a preview schema
 * may move where a stable one may not. Without both fields the gate cannot tell the two apart.
 */
final readonly class ApiSurface
{
    /**
     * The version of this snapshot's own shape.
     *
     * Distinct from every version it CONTAINS. A consumer diffing two snapshots has to know whether
     * a missing field means "removed from the contract" or "this file is shaped differently now".
     */
    public const int SCHEMA_VERSION = 1;

    /**
     * The per-rule fields that are contract, in the order they are written.
     *
     * Named as a list rather than filtered inline, because this list IS the promise: adding an entry
     * makes something breaking that was not, and removing one silently un-promises it. It should be
     * read as a decision every time it changes.
     *
     * @var list<string>
     */
    public const array RULE_FIELDS = [
        'id',
        'category',
        'level',
        'severity',
        'stability',
        'message_prefix',
        'documentation_url',
        'deprecated_since',
        'replaced_by',
    ];

    /**
     * Build the snapshot from the shipped registry.
     *
     * @param  array{entries?: list<array<string, mixed>>}  $registry  decoded rule-registry.json
     * @return array<string, mixed>
     */
    public static function of(array $registry): array
    {
        $rules = [];

        foreach ($registry['entries'] ?? [] as $entry) {
            $id = $entry['id'] ?? null;

            if (! is_string($id) || $id === '') {
                // A registry entry with no id is a broken generator, and the snapshot must not
                // paper over it: an entry silently dropped here would be a rule that left the
                // contract without the breaking-change gate ever seeing a diff — the exact failure
                // the gate exists to prevent, arriving through its own input.
                throw new MalformedRuleRegistry(
                    'A rule-registry entry carries no id. The snapshot is the contract, so an entry '
                    .'it cannot name would leave the contract silently — which is what the '
                    .'breaking-change gate reads this file to prevent. Regenerate the registry with '
                    .'`SQLENS_WRITE_RULE_REGISTRY=1` and look at what produced a nameless row.'
                );
            }

            $projected = [];

            foreach (self::RULE_FIELDS as $field) {
                // `??` rather than a presence check: a registry entry that omits an optional field
                // and one that carries it as null are the same promise, and writing them
                // differently would put a diff in the snapshot for no contract change.
                $projected[$field] = $entry[$field] ?? null;
            }

            $rules[$id] = $projected;
        }

        // Sorted by id, and sorted HERE rather than trusting the registry's order. The registry is
        // generated too, and a snapshot whose order depended on another generator's would produce a
        // diff the day that one changed its sort — a breaking-change gate firing on nothing.
        ksort($rules);

        return [
            'schema_version' => self::SCHEMA_VERSION,
            'rules' => array_values($rules),
            'exit_codes' => self::exitCodes(),
            'baseline_schema_version' => BaselineSchema::VERSION,
            'report_schema_version' => JsonEnvelope::SCHEMA_VERSION,
            // Both halves, and the second is the reason the pair exists. The remediation schema
            // ships as `preview`, and its special case in the versioning promise is precisely that
            // a preview schema may move within a minor where a stable one may not. A gate given
            // only the version could not tell which rule to apply.
            'remediation_schema_version' => RemediationPayload::SCHEMA_VERSION,
            'remediation_schema_stability' => RemediationPayload::STABILITY->value,
        ];
    }

    /**
     * The exit-code table, from the enum rather than from a list.
     *
     * @return array<string, int>
     */
    private static function exitCodes(): array
    {
        $codes = [];

        foreach (ExitCode::cases() as $case) {
            $codes[$case->name] = $case->value;
        }

        // Sorted by NAME, not by value: two codes could never share a value, but sorting by name
        // keeps the diff stable if a future code is inserted in the middle of the range.
        ksort($codes);

        return $codes;
    }
}
