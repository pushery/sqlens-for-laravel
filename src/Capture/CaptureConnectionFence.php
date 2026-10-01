<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Closure;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Events\ConnectionEstablished;
use WeakMap;

/**
 * Keeps a migration method a capture runs on the one connection the capture owns.
 *
 * Pretend mode intercepts one connection object, and shadow mode points the default connection at
 * the throwaway database. A migration that names another connection, `DB::connection('reporting')`
 * or `Schema::connection('reporting')`, reaches an object neither of them covers, and what it sends
 * there runs for real. While a method runs inside {@see self::around()}, every query on any other
 * connection is refused before it reaches its server, and the refusal ends the method the way any
 * exception does: the capture records the migration as failed, with the connection it reached.
 *
 * Every connection the manager holds carries the guard, and so does each one it opens later. Outside
 * {@see self::around()} the guard lets everything through.
 */
final class CaptureConnectionFence
{
    private ?Connection $owner = null;

    /** @var WeakMap<Connection, true> */
    private WeakMap $guarded;

    private bool $watchesNewConnections = false;

    public function __construct(
        private readonly DatabaseManager $database,
        private readonly ?Dispatcher $events = null,
    ) {
        $this->guarded = new WeakMap;
    }

    /**
     * Run a migration method with `$owner` as the only connection it may use.
     *
     * @template TResult
     *
     * @param  Closure(): TResult  $run
     * @return TResult
     */
    public function around(Connection $owner, Closure $run): mixed
    {
        foreach ($this->database->getConnections() as $connection) {
            $this->guard($connection);
        }

        if (! $this->watchesNewConnections && $this->events instanceof Dispatcher) {
            $this->events->listen(ConnectionEstablished::class, function (ConnectionEstablished $established): void {
                $this->guard($established->connection);
            });

            $this->watchesNewConnections = true;
        }

        $previous = $this->owner;
        $this->owner = $owner;

        try {
            return $run();
        } finally {
            $this->owner = $previous;
        }
    }

    private function guard(Connection $connection): void
    {
        if (isset($this->guarded[$connection])) {
            return;
        }

        $connection->beforeExecuting(function (string $query, array $bindings, Connection $reached): void {
            if ($this->owner instanceof Connection && $reached !== $this->owner) {
                throw ForeignConnectionRefused::reaching($reached->getName() ?? 'unnamed', $this->owner->getName() ?? 'unnamed');
            }
        });

        $this->guarded[$connection] = true;
    }
}
