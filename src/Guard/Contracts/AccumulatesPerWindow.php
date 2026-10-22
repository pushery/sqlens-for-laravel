<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard\Contracts;

/**
 * An inspector that keeps state across the queries of one request, job or command.
 *
 * Its own contract rather than a method on {@see QueryInspector}, because only some guardrails need
 * it: the slow-query budget, and through {@see PausesDuringMigrations} the pause of the runtime DDL
 * guardrail. A method every implementation had to define, most of them as an empty body, is a method
 * somebody eventually fills in for the wrong reason.
 *
 * ## Why any of this exists
 *
 * A queue worker or an Octane server is one process handling thousands of requests. An accumulator
 * that never resets measures the worker's uptime rather than a request, and a latch that never
 * resets reports once and then stays silent forever — which reads exactly like an application that
 * got faster.
 *
 * There is no `endWindow()`. The window ends when the next one starts, and a pair of calls would be
 * a pair somebody can get out of sync.
 */
interface AccumulatesPerWindow
{
    /**
     * Begin a fresh window: totals at zero, anything already reported forgotten, and a pause the migrator
     * never ended over.
     */
    public function startWindow(): void;
}
