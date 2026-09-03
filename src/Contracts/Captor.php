<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Capture\CaptureRun;
use Pushery\SQLens\Capture\CaptureSection;
use Pushery\SQLens\Capture\PendingMigration;
use Pushery\SQLens\Subjects\CaptureMode;

/**
 * The one contract both capture modes fulfill — pretend now, shadow later.
 *
 * It exists so the second mode cannot grow a second result shape. Two capture
 * paths that each described their own output is the start of every divergence
 * between "what lint saw" and "what the database will do".
 *
 * **The input contract is the load-bearing part.** A captor is HANDED an
 * already-resolved, already-sorted list of pending migrations and resolves
 * nothing itself: it must not reach for the migrator repository, the filesystem,
 * or a connection to decide what is pending. That resolution has exactly one
 * home (the lint command), because two resolutions would eventually disagree
 * about which migrations a run covered — and a run that quietly covered fewer
 * migrations than the user believes is a silent green.
 */
interface Captor
{
    /**
     * Capture the SQL of the given pending migrations without executing their
     * effects.
     *
     * @param  iterable<PendingMigration>  $migrations  already resolved and ordered by the caller
     */
    public function capture(iterable $migrations, CaptureSection $section): CaptureRun;

    /** Which mode this captor implements — recorded on every result it produces. */
    public function mode(): CaptureMode;
}
