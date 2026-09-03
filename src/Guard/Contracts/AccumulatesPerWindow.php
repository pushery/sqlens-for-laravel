<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard\Contracts;

/**
 * An inspector that accumulates across the queries of ONE request, job or command.
 *
 * Its own contract rather than a method on {@see QueryInspector}, because only one guardrail needs
 * it and a method every implementation had to define — most of them as an empty body — is a method
 * somebody eventually fills in for the wrong reason.
 *
 * ## Why any of this exists
 *
 * A queue worker or an Octane server is ONE process handling thousands of requests. An accumulator
 * that never resets measures the worker's uptime rather than a request, and a latch that never
 * resets reports once and then stays silent forever — which reads exactly like an application that
 * got faster.
 *
 * There is no `endWindow()`. The window ends when the next one starts, and a pair of calls would be
 * a pair somebody can get out of sync.
 */
interface AccumulatesPerWindow
{
    /** Begin a fresh window: totals at zero, and anything already reported forgotten. */
    public function startWindow(): void;
}
