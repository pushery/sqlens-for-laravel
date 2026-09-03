<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Advisory;

/**
 * One release series of one engine, with the two dates that decide whether running it is a finding.
 *
 * A cycle rather than a version: `18.4` is a patch of cycle `18`, and support ends for the cycle,
 * not for the patch. Reasoning per patch would require a file that changes every few weeks and
 * would still be wrong between updates.
 */
final readonly class EolCycle
{
    public function __construct(
        /** The release series, as the vendor names it: `18`, `8.4`, `9.1`. */
        public string $cycle,
        /**
         * The newest patch release of this cycle the data knows about, or null when it records none.
         *
         * Null in every bundled cycle, and that is a decision rather than an omission. A patch level
         * moves every few weeks, so a copy shipped inside a package is wrong within a month of any
         * release — and a wrong "latest" produces either invented findings or invented confidence,
         * which are the two failures this package exists to avoid. Read as null, the rule reports an
         * undetermined naming the gap; the explicit refresh is what fills it.
         */
        public ?string $latestPatch,
        public string $releaseDate,
        /**
         * The day routine security fixes stop.
         *
         * For MySQL this is PREMIER support rather than extended: extended support exists, costs
         * money, and is not what most projects are on. Recording the later date would let a server
         * that stopped receiving routine fixes read as supported.
         */
        public string $eolDate,
        /** Whether the vendor designates this a long-term-support series. */
        public bool $lts,
        /** Why this row says what it says — carried so a reader can check the reasoning, not only the dates. */
        public string $note,
    ) {}

    /**
     * Whether this cycle's support had ended on the given day.
     *
     * The day itself counts as still supported: an EOL date is when support ends, and treating it
     * as already over would report a finding one day early on every engine in the file.
     *
     * @param  string  $on  an ISO-8601 date. String comparison is exact for that format and needs
     *                      no timezone, which a date object would have to invent.
     */
    public function endedBy(string $on): bool
    {
        return $on > $this->eolDate;
    }
}
