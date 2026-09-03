<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Suppression;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Outcome;
use Pushery\SQLens\Rules\Suite;

/**
 * One entry of the project's `sqlens.ignore` list, parsed.
 *
 * The SHAPE of an entry — which fields exist and that `reason` is mandatory —
 * belongs to the config schema, which validates it before any of this runs. This
 * value object only interprets an entry the schema already accepted, so the rule
 * is never described twice.
 *
 * The index is carried along because it is the entry's identity: two entries can
 * be byte-identical, and reporting "the ignore at position 3 never matched" is
 * what lets someone actually find and delete it.
 */
final readonly class ConfigIgnoreRule
{
    /**
     * @param  list<string>  $paths  repo-relative globs; empty means every path
     * @param  list<Suite>  $suites  empty means every suite
     */
    public function __construct(
        public int $index,
        public string $rule,
        public string $reason,
        public array $paths = [],
        public array $suites = [],
    ) {}

    /**
     * Parse one already-validated entry.
     *
     * @param  array<string, mixed>  $entry
     */
    public static function fromConfig(int $index, array $entry): self
    {
        return new self(
            index: $index,
            rule: is_string($entry['rule'] ?? null) ? $entry['rule'] : '',
            reason: is_string($entry['reason'] ?? null) ? $entry['reason'] : '',
            paths: self::strings($entry['paths'] ?? []),
            suites: array_values(array_filter(array_map(
                Suite::tryFrom(...),
                self::strings($entry['suites'] ?? []),
            ))),
        );
    }

    /** Whether this ignore covers the finding in a run of the given suite. */
    public function covers(Finding $finding, Suite $suite, bool $allowUndetermined = false): bool
    {
        // An undetermined is not suppressed by default, by any layer. A check that
        // could not run is not a finding somebody chose to ignore, and hiding it
        // would hide the fact that it never ran. Only the resolver, holding the
        // project's explicit per-reason allowance, may lift this.
        if (! $allowUndetermined && $finding->status->outcome === Outcome::Undetermined) {
            return false;
        }

        if ($finding->ruleId !== $this->rule) {
            return false;
        }

        if ($this->suites !== [] && ! in_array($suite, $this->suites, true)) {
            return false;
        }

        return $this->matchesPath($finding);
    }

    /**
     * A path filter narrows an ignore to part of the repo. A finding with no file
     * — a catalog object, say — is therefore NOT covered by a path-scoped ignore:
     * the entry says "here", and a catalog object is not there.
     */
    private function matchesPath(Finding $finding): bool
    {
        if ($this->paths === []) {
            return true;
        }

        $file = $finding->location->file;

        if ($file === null) {
            return false;
        }

        return array_any($this->paths, fn (string $glob): bool => PathGlob::matches($glob, $file));
    }

    /**
     * @return list<string>
     */
    private static function strings(mixed $value): array
    {
        return is_array($value)
            ? array_values(array_filter($value, is_string(...)))
            : [];
    }
}
