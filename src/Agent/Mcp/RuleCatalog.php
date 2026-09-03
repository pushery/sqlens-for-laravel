<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

use Pushery\SQLens\Catalog\RuleRegistryExport;

/**
 * The shipped rule registry, read.
 *
 * ## Why the bundled file rather than the live registry
 *
 * The file is what a release CONTAINS, and it is regenerated from the live registry by a build step
 * that a guard holds to the tree. Reading it here means an agent is told exactly what the release
 * documents — the same rows the documentation pages and the agent-rules export are built from. A
 * second walk over the live registry would be a second description of one rule, free to disagree
 * with the published one about a release that already shipped.
 *
 * It also costs nothing: no container, no driver resolution, no database. A tool that only explains
 * a rule has no business booting an engine.
 *
 * ## Why unknown is answered with suggestions rather than with nothing
 *
 * A caller that mistypes an id and receives silence concludes the rule does not matter. The
 * distance ceiling is deliberate — an unbounded nearest match answers a wholly invented id with a
 * confident and unrelated suggestion, which is worse than admitting there is none.
 */
final class RuleCatalog
{
    /** How far a suggestion may be from what was asked, before it stops being a suggestion. */
    private const int MAX_SUGGESTION_DISTANCE = 8;

    /** At most this many, so a refusal stays readable. */
    private const int MAX_SUGGESTIONS = 3;

    /** @var array<string, array<string, mixed>>|null */
    private ?array $rows = null;

    public function __construct(private readonly ?string $path = null) {}

    /**
     * One rule's published metadata, or null when this build registers no such id.
     *
     * @return array<string, mixed>|null
     */
    public function find(string $ruleId): ?array
    {
        return $this->rows()[$ruleId] ?? null;
    }

    /**
     * Every registered id, in the order the shipped file holds them.
     *
     * @return list<string>
     */
    public function ids(): array
    {
        return array_keys($this->rows());
    }

    /**
     * The registered ids closest to what was asked, nearest first.
     *
     * @return list<string>
     */
    public function closestTo(string $ruleId): array
    {
        $scored = [];

        foreach ($this->ids() as $candidate) {
            $distance = levenshtein(strtoupper($ruleId), strtoupper($candidate));

            if ($distance <= self::MAX_SUGGESTION_DISTANCE) {
                $scored[$candidate] = $distance;
            }
        }

        // Distance first, then the id itself — a tie broken by array order would depend on the file
        // and make one question answerable two ways across releases.
        uksort($scored, static fn (string $a, string $b): int => $scored[$a] <=> $scored[$b] ?: strcmp($a, $b));

        return array_slice(array_keys($scored), 0, self::MAX_SUGGESTIONS);
    }

    /** @return array<string, array<string, mixed>> */
    private function rows(): array
    {
        if ($this->rows !== null) {
            return $this->rows;
        }

        $path = $this->path ?? dirname(__DIR__, 3).'/'.RuleRegistryExport::BUNDLED_FILE;
        $raw = @file_get_contents($path);
        $decoded = $raw === false ? null : json_decode($raw, true);
        $rows = [];

        if (is_array($decoded) && is_array($decoded['entries'] ?? null)) {
            foreach ($decoded['entries'] as $row) {
                if (! is_array($row)) {
                    continue;
                }
                if (! is_string($row['id'] ?? null)) {
                    continue;
                }
                // Keys narrowed to strings here rather than trusted from the decode: a JSON object
                // decodes to a string-keyed array, but PHP silently turns a numeric-looking key
                // into an int — and one such key would make this map a shape its readers do not
                // expect, for a file somebody hand-edited.
                $narrowed = [];

                foreach ($row as $key => $value) {
                    $narrowed[(string) $key] = $value;
                }

                $rows[$row['id']] = $narrowed;
            }
        }

        return $this->rows = $rows;
    }
}
