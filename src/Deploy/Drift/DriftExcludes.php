<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

/**
 * The accepted differences, applied to a comparison.
 *
 * ## It withdraws entries; it does not touch the blind spots
 *
 * A blind spot is not a difference somebody could accept — it is a part of the schema that was never
 * compared. An exclude file that could silence one would let a project turn "we cannot read indexes
 * here" into a clean report with a reason attached, which is the single most valuable thing this
 * comparison has to say. So {@see DriftReport::$blindSpots} travels through untouched, and a run
 * carrying one stays inconclusive however many exclusions it has.
 *
 * ## A stale entry is reported, never dropped quietly
 *
 * An entry that covered nothing is collected and handed back. Excludes that nobody prunes grow into
 * a ceiling under which real drift disappears — and the growth is invisible, because a file with
 * forty lines looks exactly like a file with four that are still true.
 */
final readonly class DriftExcludes
{
    /**
     * @param  list<DriftExcludeEntry>  $entries
     */
    public function __construct(private array $entries) {}

    public static function from(DriftExcludeFile $file): self
    {
        return new self($file->entries);
    }

    /** Whether anything at all was accepted — a project with no file gets the cheap path. */
    public function isEmpty(): bool
    {
        return $this->entries === [];
    }

    /**
     * The report with accepted differences withdrawn, plus what that cost and what has rotted.
     *
     * Both halves are walked in one pass: an entry is "used" the moment it covers something, so the
     * stale set is what is left over rather than a second comparison that could disagree with the
     * first.
     */
    public function applyTo(DriftReport $report): DriftExcludeOutcome
    {
        $used = [];
        $kept = [];

        foreach ($report->entries as $entry) {
            $covering = array_find(
                $this->entries,
                static fn (DriftExcludeEntry $exclude): bool => $exclude->covers($entry),
            );

            if ($covering instanceof DriftExcludeEntry) {
                $used[$covering->sortKey()] = true;

                continue;
            }

            $kept[] = $entry;
        }

        $stale = array_values(array_filter(
            $this->entries,
            static fn (DriftExcludeEntry $exclude): bool => ! isset($used[$exclude->sortKey()]),
        ));

        return new DriftExcludeOutcome(
            new DriftReport($kept, $report->blindSpots),
            count($report->entries) - count($kept),
            $stale,
        );
    }

    /**
     * The reason `--update-excludes` writes, and the next read REFUSES it.
     *
     * Three candidates, and only this one is honest. An empty string would be refused too, but a
     * generated file full of empty fields reads like a bug rather than an obligation. An invented,
     * plausible reason would be the worst of the three — it makes an unreviewed exclusion look
     * reviewed. A work marker would be neither, and it would ship a leftover-work word into a
     * released package, where the leak guard rightly refuses it.
     *
     * So the placeholder says what it is, and {@see DriftExcludeFile} rejects it by name. A
     * generated file is therefore UNUSABLE until a person edits it, which is the obligation made
     * mechanical rather than merely visible.
     */
    public const string UNEXPLAINED = 'unexplained: replace this with why the difference is deliberate, or delete the entry';

    /**
     * An entry per difference in a report, with the placeholder reason `--update-excludes` writes.
     *
     * A divergence is written WITHOUT an attribute — the object whole. Narrowing it to one attribute
     * is a judgment about which part is deliberate, and a generator has no basis for that.
     *
     * @return list<DriftExcludeEntry>
     */
    public static function proposalsFor(DriftReport $report): array
    {
        return array_map(
            static fn (DriftEntry $entry): DriftExcludeEntry => new DriftExcludeEntry(
                $entry->type,
                $entry->qualifiedName,
                null,
                self::UNEXPLAINED,
            ),
            $report->entries,
        );
    }
}
