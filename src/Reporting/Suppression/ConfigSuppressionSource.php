<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Suppression;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Rules\Suite;

/**
 * The second suppression layer: the project's own `sqlens.ignore` list — chosen
 * deliberately, documented with a reason, and never silently inert.
 *
 * "Never silently inert" is the load-bearing half. An ignore entry that matches
 * nothing in a whole run is reported, exactly like a stale baseline entry: it
 * means either the finding is long fixed (delete the entry) or the entry never
 * worked at all (fix it). Both are worth knowing, and neither is visible if the
 * list is only ever read and never accounted for. A typo'd rule id is a harder
 * error still, and has its own ticket.
 *
 * The list's SHAPE — and that `reason` is mandatory — is the config schema's
 * business; it has already validated the entries before this source sees them.
 */
final readonly class ConfigSuppressionSource
{
    /** The suppression-source name a resolver records on a finding it hides. */
    public const string SOURCE = 'config';

    /** @param  list<ConfigIgnoreRule>  $rules */
    public function __construct(public array $rules) {}

    /** Build from the validated `sqlens.ignore` config value. */
    public static function fromConfig(mixed $ignore): self
    {
        if (! is_array($ignore)) {
            return new self([]);
        }

        $rules = [];

        foreach (array_values($ignore) as $index => $entry) {
            if (is_array($entry)) {
                /** @var array<string, mixed> $entry */
                $rules[] = ConfigIgnoreRule::fromConfig($index, $entry);
            }
        }

        return new self($rules);
    }

    /**
     * The ignore covering this finding in a run of the given suite, or null. The
     * first matching entry wins, in the order the config declares them — so the
     * reported reason is always the same one for the same config.
     */
    public function suppressionFor(Finding $finding, Suite $suite, bool $allowUndetermined = false): ?ConfigIgnoreRule
    {
        foreach ($this->rules as $rule) {
            if ($rule->covers($finding, $suite, $allowUndetermined)) {
                return $rule;
            }
        }

        return null;
    }

    /**
     * The entries that covered nothing in this run — same accounting as a stale
     * baseline entry, and reported in config order so the output is stable.
     *
     * @param  list<int>  $usedIndices  the indices suppressionFor() returned during the run
     * @return list<ConfigIgnoreRule>
     */
    public function unusedRules(array $usedIndices): array
    {
        return array_values(array_filter(
            $this->rules,
            static fn (ConfigIgnoreRule $rule): bool => ! in_array($rule->index, $usedIndices, true),
        ));
    }
}
