<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Baseline;

use Pushery\SQLens\Severity\Severity;

/**
 * A baseline as a value: the entries it accepts, held in the ONE documented
 * order the file is written in.
 *
 * The order is subject, then rule id, then ordinal, then fingerprint — never the
 * order a run happened to produce, and never a filesystem or hash order. Sorting
 * by subject first is what makes the file readable (everything about one
 * migration sits together) and what makes a diff small (a change in one migration
 * touches one region of the file). The fingerprint is the last tiebreaker so the
 * order is TOTAL: two entries that agree on all three leading keys still have a
 * defined position, which is what "same state, same file" requires.
 *
 * The baseline is a repo FILE, never a database table — the tool writes no
 * database state at all.
 */
final readonly class BaselineFile
{
    /** @param  list<BaselineEntry>  $entries  already in the documented order */
    private function __construct(public array $entries) {}

    /**
     * The path a baseline is written to when the project has not named one.
     * The config key `sqlens.baseline.path` (declared by the config schema, only
     * read here) defaults to null, which means "apply no baseline" — a different
     * statement from "where does a baseline live", which is this.
     */
    public const string DEFAULT_PATH = '.sqlens-baseline.json';

    /** @param  list<BaselineEntry>  $entries  in any order */
    public static function of(array $entries): self
    {
        usort($entries, self::order(...));

        return new self($entries);
    }

    public function isEmpty(): bool
    {
        return $this->entries === [];
    }

    /** Whether an entry with this identity is recorded. */
    public function has(BaselineEntry $entry): bool
    {
        return array_any($this->entries, fn (BaselineEntry $recorded): bool => $recorded->key() === $entry->key());
    }

    /** The severity as a sortable string — the empty string for an entry that carries none. */
    private static function severityKey(BaselineEntry $entry): string
    {
        return $entry->severity instanceof Severity ? $entry->severity->value : '';
    }

    /**
     * The documented total order. Every comparison is a plain byte comparison, so
     * it cannot depend on the process locale.
     */
    private static function order(BaselineEntry $a, BaselineEntry $b): int
    {
        return strcmp($a->subject, $b->subject)
            ?: strcmp($a->ruleId, $b->ruleId)
            ?: $a->ordinal <=> $b->ordinal
            // Severity before the fingerprint, so two entries that differ only in risk sort by the
            // thing a reader cares about rather than by a hash. The fingerprint stays last as the
            // total order — every earlier key can tie, and a sort that can tie is not deterministic.
            ?: strcmp(self::severityKey($a), self::severityKey($b))
            ?: strcmp($a->fingerprint->value, $b->fingerprint->value);
    }
}
