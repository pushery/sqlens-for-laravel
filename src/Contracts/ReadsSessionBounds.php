<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Catalog\ReaderSession;
use Throwable;

/**
 * Reads back the timeouts a session actually has in force.
 *
 * ## Why this is an interface and not just a method on the check
 *
 * The run header shows these numbers, and it takes them from the SAME call the check judges on —
 * two reads of one fact are two chances to disagree, and the disagreement would surface as a header
 * claiming a bound beside a verdict saying there is none.
 *
 * That shared call needs a failure path, because the read can fail: under transaction pooling a
 * `SET` is accepted and quietly stops applying, and a dropped connection answers nothing at all.
 * When it does, the header must go SILENT rather than fall back to what was asked for.
 *
 * The seam exists so that path can be proved. Constructed inline, the only route into it was a real
 * connection dying mid-run — which no suite can stage, and which made the branch an untested claim
 * sitting on the line that decides what a deploy operator reads about their own session bounds.
 * A `final readonly` class cannot be doubled either, and the attempt fails as a COMPILE error: an
 * empty log, exit 1, and zero reported failures.
 */
interface ReadsSessionBounds
{
    /**
     * The timeouts actually in force, in milliseconds.
     *
     * Takes the SESSION and the engine that answers for it, not a whole context. The reading is
     * about a session — which is why a second caller could ask for it: `sqlens:postdeploy` opens
     * the same sealed session and owes its reader the same header, but it has no pending work and
     * therefore no `PreflightContext` to hand over. Widening a value object to fit an argument
     * list is how a context turns into a bag; narrowing the argument to what is actually read
     * keeps both callers honest.
     *
     * @return array<string, int|null>
     *
     * @throws Throwable when the session will not say — the caller decides between a named
     *                   `undetermined` and a silent header, and neither may become a default
     */
    public function inForce(string $driver, ReaderSession $session): array;
}
