<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard\Guards;

use Illuminate\Database\Events\QueryExecuted;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Guard\Contracts\AccumulatesPerWindow;
use Pushery\SQLens\Guard\Contracts\QueryInspector;
use Pushery\SQLens\Guard\GuardProfile;
use Pushery\SQLens\Guard\ViolationLogger;
use Pushery\SQLens\Guard\Violations\Violation;

/**
 * Two thresholds, and the second one is the reason this exists.
 *
 * A per-query threshold catches the one statement that took two seconds. It is blind to the shape
 * that actually takes a page down: four hundred queries of four milliseconds each, none of them
 * remotely slow, adding up to a second and a half of database time in one request. That is an N+1,
 * and no per-query number will ever see it.
 *
 * So a cumulative budget runs beside it. When a request crosses it, the report says how many
 * queries got it there — which is the number that names the cause.
 *
 * ## The per-request state lives HERE, and it is deliberately not on a singleton
 *
 * `phpstan.neon.dist` runs `checkOctaneCompatibility: true`: a container singleton holding request
 * state survives into the next request under Octane, and the accumulated total would then be the
 * sum of two unrelated requests. This object is built once per activation and the counter is reset
 * the moment it reports, so the worst case is one request's worth of over-counting rather than an
 * ever-growing number nobody can explain.
 */
final class SlowQueryGuard implements AccumulatesPerWindow, QueryInspector
{
    /**
     * The ONE sentence that points at the APM layer, owned here and quoted nowhere else.
     *
     * A slow query is where somebody starts wanting trends, percentiles and history — and this
     * package deliberately provides none of those. Saying so in the finding itself, rather than only
     * in a documentation page nobody reads at 3 a.m., is what keeps the boundary from being
     * relitigated: the reader learns where the answer lives at the moment they want it.
     *
     * A constant rather than four inlined copies, so the message and the documentation cannot drift
     * apart — a boundary stated two ways is a boundary somebody argues with.
     */
    public const string APM_BOUNDARY = 'SQLens reports this once, here. Trends, percentiles and '
        .'history are an APM question — Laravel Pulse, Sentry or whatever you already run — and this '
        .'package deliberately keeps none of them.';

    private float $accumulatedMs = 0.0;

    private int $queries = 0;

    private bool $reported = false;

    public function __construct(private readonly ViolationLogger $logger) {}

    /**
     * Start a fresh accounting window — one request, one job, one command.
     *
     * ⚠️ WITHOUT THIS THE CUMULATIVE CHECK IS DEAD FROM THE SECOND JOB ONWARD, and dead in the way
     * that looks healthiest: a queue worker or an Octane server is ONE process handling thousands of
     * requests, so a latch that never resets reports the first one that crosses the budget and then
     * stays silent forever. Nothing goes red. The log simply never mentions it again, which reads
     * exactly like an application that got faster.
     *
     * The totals reset too, not just the latch. Carrying them across requests would make the budget
     * a measurement of the worker's uptime — every long-lived process crosses any threshold
     * eventually, and the report would name whichever request happened to be running.
     */
    public function startWindow(): void
    {
        $this->accumulatedMs = 0.0;
        $this->queries = 0;
        $this->reported = false;
    }

    public function appliesTo(GuardProfile $profile): bool
    {
        return $profile->slowQueryEnabled;
    }

    public function inspect(QueryExecuted $query, GuardProfile $profile): void
    {
        $this->accumulatedMs += $query->time;
        $this->queries++;

        if ($query->time >= $profile->slowQueryThresholdMs) {
            $this->logger->record($profile, Violation::found(
                type: 'slow_query',
                category: Category::Performance,
                message: 'a query took longer than this profile allows. '.self::APM_BOUNDARY,
                connection: $query->connectionName,
                sql: $query->sql,
                bindings: $query->bindings,
                context: ['time_ms' => $query->time, 'threshold_ms' => $profile->slowQueryThresholdMs],
            ));
        }

        if ($this->reported || $this->accumulatedMs < $profile->cumulativeThresholdMs) {
            return;
        }

        // ONCE per request, not once per query past the line. Without the latch a request that went
        // 10 ms over its budget would log every remaining query it ran — hundreds of lines saying
        // the same thing, which is how a log stops being read.
        $this->reported = true;

        $this->logger->record($profile, Violation::found(
            type: 'cumulative_query_time',
            category: Category::Performance,
            message: 'this request spent more time in the database than the profile allows. '.self::APM_BOUNDARY,
            connection: $query->connectionName,
            sql: $query->sql,
            bindings: $query->bindings,
            context: [
                // The COUNT is the diagnosis. One slow query and four hundred fast ones reach the
                // same total and need opposite fixes, and this is the only field that tells them
                // apart.
                'queries' => $this->queries,
                'total_ms' => round($this->accumulatedMs, 2),
                'threshold_ms' => $profile->cumulativeThresholdMs,
            ],
        ));
    }
}
