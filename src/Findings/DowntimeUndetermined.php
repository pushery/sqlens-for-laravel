<?php

declare(strict_types=1);

namespace Pushery\SQLens\Findings;

/**
 * A statement whose downtime class could not be determined, and why.
 *
 * The class of a MySQL statement comes from the online-DDL matrix, per operation and server
 * version, and some entries depend on the live table: a `DROP COLUMN` is instant unless the column
 * carries a functional index, the table is out of row versions, and two more conditions. A run
 * that did not look at the table cannot settle that, and a finding that then carried no class read
 * as a finding that makes no claim about downtime, which is the opposite of what it is.
 *
 * It is not a fourth downtime class. The classes are a closed set a deploy script ranks, and
 * "unknown" has no place in that order: it is the absence of a rank, with its reason beside it.
 */
final readonly class DowntimeUndetermined
{
    public function __construct(
        public UndeterminedReason $reason,
        public ?string $detail = null,
    ) {}

    /**
     * @return array{reason: string, detail?: string}
     */
    public function toArray(): array
    {
        $array = ['reason' => $this->reason->value];

        if ($this->detail !== null) {
            $array['detail'] = $this->detail;
        }

        return $array;
    }
}
