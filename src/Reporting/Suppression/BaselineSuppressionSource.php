<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Suppression;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Outcome;
use Pushery\SQLens\Reporting\Baseline\BaselineEntry;
use Pushery\SQLens\Reporting\Baseline\BaselineFile;
use Pushery\SQLens\Reporting\Baseline\FindingFingerprint;

/**
 * The first suppression layer: match findings against the accepted-findings
 * ledger by fingerprint.
 *
 * Two rules make this layer honest rather than a mute filter.
 *
 * A match is a STATEMENT, not a disappearance. This source only says which entry
 * covers which finding; hiding it from the gate while keeping it in the balance
 * is the resolver's job, and nothing here deletes anything.
 *
 * And an `undetermined` is NEVER suppressed. A check that could not run is not a
 * finding somebody accepted — baselining it would permanently hide the fact that
 * it never ran, which is precisely the silent green this package exists to
 * refuse. It stays visible no matter what the file says.
 */
final readonly class BaselineSuppressionSource
{
    /** The suppression-source name a resolver records on a finding it hides. */
    public const string SOURCE = 'baseline';

    public function __construct(private BaselineFile $baseline) {}

    /**
     * The baseline entry covering this finding, or null.
     *
     * The fingerprint and ordinal are passed in rather than derived here: the
     * fingerprint needs the CANONICAL excerpt, which only the pipeline that
     * canonicalized the statement holds.
     */
    public function suppressionFor(Finding $finding, FindingFingerprint $fingerprint, int $ordinal, bool $allowUndetermined = false): ?BaselineEntry
    {
        // Refusing by default keeps this layer safe on its own; only the resolver,
        // holding the project's explicit per-reason allowance, may lift it.
        if (! $allowUndetermined && $finding->status->outcome === Outcome::Undetermined) {
            return null;
        }

        $key = $fingerprint->value.'#'.$ordinal;

        foreach ($this->baseline->entries as $entry) {
            if ($entry->key() === $key) {
                return $entry;
            }
        }

        return null;
    }

    /**
     * The recorded entries that covered nothing in this run.
     *
     * Without this the file grows shut: entries pile up for findings fixed months
     * ago and the baseline stops describing what the project actually accepts.
     *
     * An entry whose SOURCE could not answer this run is not stale — see
     * {@see self::unverifiableEntries()} for why that distinction is not a nicety.
     *
     * @param  list<string>  $matchedKeys  the keys suppressionFor() returned during the run
     * @param  list<string>  $unverifiablePrefixes  rule-id prefixes whose source did not answer
     * @return list<BaselineEntry> in the file's own order, so the report is stable
     */
    public function staleEntries(array $matchedKeys, array $unverifiablePrefixes = []): array
    {
        return array_values(array_filter(
            $this->baseline->entries,
            fn (BaselineEntry $entry): bool => ! in_array($entry->key(), $matchedKeys, true)
                && ! $this->isUnverifiable($entry, $unverifiablePrefixes),
        ));
    }

    /**
     * The entries this run could not check at all — an accepted finding from a source that did
     * not answer, not one that was fixed.
     *
     * The distinction is the whole point. "Stale" means the problem is gone and the line can go
     * with it; telling somebody that about an entry NOBODY LOOKED AT sends them to delete a line
     * that comes straight back on the next machine that has the tool. Reported under its own
     * name and kept in the file.
     *
     * @param  list<string>  $matchedKeys
     * @param  list<string>  $unverifiablePrefixes  rule-id prefixes whose source did not answer
     * @return list<BaselineEntry>
     */
    public function unverifiableEntries(array $matchedKeys, array $unverifiablePrefixes): array
    {
        return array_values(array_filter(
            $this->baseline->entries,
            fn (BaselineEntry $entry): bool => ! in_array($entry->key(), $matchedKeys, true)
                && $this->isUnverifiable($entry, $unverifiablePrefixes),
        ));
    }

    /** @param  list<string>  $prefixes */
    private function isUnverifiable(BaselineEntry $entry, array $prefixes): bool
    {
        return array_any($prefixes, fn (string $prefix): bool => str_starts_with($entry->ruleId, $prefix));
    }
}
