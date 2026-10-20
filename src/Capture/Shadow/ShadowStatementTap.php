<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

use Closure;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use WeakMap;

/**
 * Hands each query a shadow run executes to the collector of the run that is recording.
 *
 * A connection reports its queries through the event dispatcher that every connection of the
 * application shares, and Laravel offers no way to remove one listener from it: `forget()` drops
 * every listener of the event, the host application's included. A listener per run would stay for
 * the life of the process, and a process that lives for an editor session, the MCP server, would
 * collect one per shadow lint, each recording every later query into a collector nobody reads.
 *
 * So a dispatcher carries one listener, registered the first time a run records through it, and the
 * listener records only while {@see self::recording()} runs. A nested call records into its own
 * collector and hands the outer one back when it ends. A connection without a dispatcher reports no
 * query, and nothing is recorded for it.
 */
final class ShadowStatementTap
{
    /** @var WeakMap<Dispatcher, true> */
    private WeakMap $tapped;

    private ?ShadowStatementCollector $collector = null;

    public function __construct()
    {
        $this->tapped = new WeakMap;
    }

    /**
     * Run `$run` with every query the connection's dispatcher reports meanwhile recorded into `$collector`.
     *
     * @template TResult
     *
     * @param  Closure(): TResult  $run
     * @return TResult
     */
    public function recording(Connection $connection, ShadowStatementCollector $collector, Closure $run): mixed
    {
        $events = $connection->getEventDispatcher();

        if ($events !== null && ! isset($this->tapped[$events])) {
            $connection->listen(function (QueryExecuted $query): void {
                $this->collector?->record($query->sql, $query->bindings);
            });

            $this->tapped[$events] = true;
        }

        $outer = $this->collector;
        $this->collector = $collector;

        try {
            return $run();
        } finally {
            $this->collector = $outer;
        }
    }
}
