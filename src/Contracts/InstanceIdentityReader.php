<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Catalog\InstanceIdentity;

/**
 * Asks a server who it is — the one place the engine-specific way of doing that is allowed to live.
 *
 * `inet_server_addr()` and `@@hostname` are engine vocabulary, and the core namespaces are held
 * free of it by an architecture test. Without this contract, every consumer that needs to name the
 * instance a finding is about — the instance resolver, the read/write host pinning, the report
 * header — would have to carry a driver branch, and each would be a place the two engines could
 * drift apart.
 *
 * An implementation reads and nothing else: no lock, no write, no connection of its own. It is
 * handed the session the catalog reader already opened and defended.
 */
interface InstanceIdentityReader
{
    /**
     * Read the identity of the instance this session is connected to.
     *
     * Never throws for a field it cannot obtain. A missing privilege, a managed database that
     * withholds a setting, a Unix socket that has no address — each becomes a named reason on the
     * returned identity, because a reader that threw would turn an ordinary local setup into a
     * failed audit, and one that guessed would put a wrong instance in the report header.
     */
    public function read(string $connection): InstanceIdentity;
}
