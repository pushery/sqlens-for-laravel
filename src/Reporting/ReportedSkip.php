<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting;

/**
 * One area a run could not read, and why — in the header rather than in a footnote.
 *
 * ## Why the reason travels with the count
 *
 * "3 skipped" and "3 skipped: no privilege on pg_stat_statements" are different reports. The first
 * is a number a reader can only shrug at; the second is a grant somebody can fix. And the number
 * alone is worse than useless when it is small: a reader who sees "1 skipped" beside a clean
 * summary reasonably concludes the run was fine, when the one skipped area may be the only place
 * the problem could have shown up.
 *
 * That is the reason this is a value object and not an int on the header. A count is easy to carry
 * and impossible to act on, and a header that carried only the count would satisfy every
 * completeness test while telling nobody anything.
 *
 * The skips are already findings in the result — each one is reported as an `undetermined` with
 * its named reason. They appear in the header TOO because the header is what gets read first, and
 * a run that skipped half the catalog must not look complete at a glance.
 */
final readonly class ReportedSkip
{
    public function __construct(
        /** What could not be read — a catalog area, a reader, a settings group. */
        public string $area,
        /** The named reason, from the shared vocabulary rather than free prose. */
        public string $reason,
        /** What sharpens it: the object, the privilege, the error code. */
        public ?string $detail = null,
    ) {}

    /**
     * @return array{area: string, reason: string, detail: string|null}
     */
    public function toArray(): array
    {
        return [
            'area' => $this->area,
            'reason' => $this->reason,
            'detail' => $this->detail,
        ];
    }

    /** One line for the console header — the area, its reason, and what sharpens it. */
    public function describe(): string
    {
        return $this->area.': '.$this->reason.($this->detail === null ? '' : ' — '.$this->detail);
    }

    /** Stable ordering, so two runs over the same state print the same header byte for byte. */
    public function sortKey(): string
    {
        return $this->area.'|'.$this->reason.'|'.($this->detail ?? '');
    }
}
