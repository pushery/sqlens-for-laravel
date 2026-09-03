<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Usage;

/**
 * How often each index has been read, and since when the server has been counting.
 *
 * ## Why this is its own reading and not part of the snapshot
 *
 * A `CatalogSnapshot` promises determinism: the same database and the same request produce a
 * byte-identical result. Usage counters do not have that property — they move while nobody changes
 * the schema, and the window they cover starts at a moment the server chose. Folding them into the
 * snapshot would put a moving value inside the one structure the drift comparison depends on being
 * still.
 *
 * So they travel beside it, through their own named accessor on the reader contract. That is also
 * what keeps the statistics reader the audit suite grows later a SIBLING of the catalog reader
 * rather than a second, parallel way into the same views.
 *
 * ## The window is the whole difficulty
 *
 * "This index has never been scanned" is only a statement about anything if you know how long the
 * server has been counting. Three cases, and only one of them is a verdict:
 *
 * - **The counters were never reset.** `stats_reset` is NULL — the ordinary state of a fresh
 *   cluster, and measured as such on PostgreSQL 18.4. The window begins at a moment nobody recorded,
 *   so a zero count says nothing at all.
 * - **They were reset recently.** The window is real but too short to conclude from.
 * - **They were reset long enough ago.** Now a zero is evidence.
 *
 * The reading reports the fact and takes no view. Which of the three a project is in — and how long
 * "long enough" is — belongs to the rule and its configuration.
 */
final readonly class IndexUsageReading
{
    /**
     * @param  array<string, int>  $scans  index qualified name => how often it has been scanned
     * @param  string|null  $statsResetAt  when the counters were last reset, as the server spells it,
     *                                     or null when they never were. Kept as the server's own
     *                                     string rather than parsed into a date: it travels into a
     *                                     finding for a human to read, and re-formatting it would
     *                                     mean choosing a timezone this package has no business
     *                                     choosing.
     * @param  int|null  $windowDays  how many whole days the counters have been running, as the
     *                                SERVER computed it, or null when the window start is unknown.
     *                                Computed there rather than here on purpose: the server is the
     *                                one clock both the counter and its reset point were stamped
     *                                by, and a second clock in PHP could disagree with it by more
     *                                than the threshold a rule is comparing against.
     * @param  bool  $available  whether the statistics could be read at all. False is NOT the same
     *                           as an empty reading: a server that answered "no indexes have been
     *                           scanned" and one whose statistics view could not be read look
     *                           identical from the counts alone, and only one of them is a fact.
     */
    public function __construct(
        public array $scans = [],
        public ?string $statsResetAt = null,
        public ?int $windowDays = null,
        public bool $available = true,
    ) {}

    /** The reading a driver returns when it cannot answer at all. */
    public static function unavailable(): self
    {
        return new self([], null, null, false);
    }

    /**
     * How often this index was scanned, or null when the reading does not cover it.
     *
     * Null rather than zero, and the distinction is the point: an index absent from the reading was
     * not counted, which is a different statement from one that was counted and never used.
     */
    public function scansOf(string $index): ?int
    {
        return $this->scans[$index] ?? null;
    }
}
