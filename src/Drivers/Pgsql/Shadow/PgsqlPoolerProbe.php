<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Shadow;

use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionResolverInterface;
use Pushery\SQLens\Catalog\PoolerVerdict;
use Pushery\SQLens\Contracts\PoolerProbe;
use Pushery\SQLens\Drivers\Pgsql\Catalog\PgsqlPoolerReader;

/**
 * The shadow captor's view of the pooling question — the SAME heuristic, read with the other bias.
 *
 * Two callers ask "is this connection multiplexed?" and they need different things from a maybe. The
 * audit cannot speak about the instance without knowing, so an unclear answer degrades it. The
 * shadow captor only needs to know whether its template operations will work: a false positive there
 * blocks a connection that would have been fine, while a false negative surfaces immediately as a
 * failed template operation the user can act on.
 *
 * Two biases, deliberately not two heuristics. The measurement lives once, in
 * {@see PgsqlPoolerReader}, and this class is where the shadow bias is applied and named. When the
 * tells improve, both callers improve — which would not happen with a second copy that reads
 * perfectly correct on its own.
 */
final readonly class PgsqlPoolerProbe implements PoolerProbe
{
    public function __construct(private ConnectionResolverInterface $connections) {}

    public function isTransactionPooled(string $connectionName): bool
    {
        $connection = $this->connections->connection($connectionName);

        // Only a MEASURED pooler blocks the shadow path. `undetermined` answers false on purpose:
        // that is the shadow bias in one line, and the failure it accepts announces itself.
        return $connection instanceof Connection
            && new PgsqlPoolerReader($connection)->read()->verdict === PoolerVerdict::Transaction;
    }
}
