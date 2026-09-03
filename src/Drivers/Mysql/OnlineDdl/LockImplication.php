<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\OnlineDdl;

/**
 * The lock InnoDB holds on the table while a DDL operation runs.
 *
 * `None` leaves the table fully available; `Shared` lets other sessions read but not write
 * for the duration; `Exclusive` blocks reads and writes both. It is the axis the algorithm
 * does not fully capture — a COPY under a shared lock still serves reads, and the distinction
 * decides whether a rewrite is an outage or merely slow.
 */
enum LockImplication: string
{
    case None = 'none';
    case Shared = 'shared';
    case Exclusive = 'exclusive';
}
