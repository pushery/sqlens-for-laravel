<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Closure;
use Illuminate\Database\Connection;
use WeakMap;

/**
 * Records each statement a connection is about to run the way PDO receives it: the SQL with its
 * placeholders, and the bindings beside it.
 *
 * Pretend mode needs this because Laravel's pretend log is not that shape. `Connection::logQuery()`
 * writes the bindings into the text before it logs, with a scanner that reads `\'` as an escape on
 * every driver. On PostgreSQL a backslash in an ordinary literal is a character, so behind `'C:\'`
 * the scanner takes the literal to go on, and the placeholder after it stays empty. Taken as PDO
 * receives it, the statement goes through the same substitution as a shadow capture instead, and
 * both modes give the same text.
 *
 * One callback per connection, registered with `beforeExecuting()` the first time the connection is
 * recorded, and live only while {@see self::recording()} runs for that connection. Laravel offers no
 * way to remove such a callback, and one per capture would pile up on a connection a long process
 * keeps open. `beforeExecuting()` needs no event dispatcher, and it runs inside the same
 * `Connection::run()` call that logs the statement, so what is recorded here and what the pretend log
 * holds describe the same statements, one for one.
 */
final class PretendStatementTap
{
    /** @var WeakMap<Connection, true> */
    private WeakMap $tapped;

    private ?Connection $recorded = null;

    /** @var list<array{sql: string, bindings: list<mixed>}> */
    private array $statements = [];

    public function __construct()
    {
        $this->tapped = new WeakMap;
    }

    /**
     * Run `$run` and answer its result with every statement `$connection` was about to execute meanwhile.
     *
     * A statement another connection runs is not recorded, and neither is one outside `$run`. A nested
     * call records for its own connection and hands the outer recording back when it ends.
     *
     * @template TResult
     *
     * @param  Closure(): TResult  $run
     * @return array{0: TResult, 1: list<array{sql: string, bindings: list<mixed>}>}
     */
    public function recording(Connection $connection, Closure $run): array
    {
        if (! isset($this->tapped[$connection])) {
            $connection->beforeExecuting(function (string $query, array $bindings, Connection $reached): void {
                if ($reached === $this->recorded) {
                    $this->statements[] = ['sql' => $query, 'bindings' => array_values($bindings)];
                }
            });

            $this->tapped[$connection] = true;
        }

        $outer = [$this->recorded, $this->statements];
        $this->recorded = $connection;
        $this->statements = [];

        try {
            $result = $run();

            return [$result, $this->statements];
        } finally {
            [$this->recorded, $this->statements] = $outer;
        }
    }
}
