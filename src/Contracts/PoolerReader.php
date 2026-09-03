<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Catalog\PoolerReading;
use Pushery\SQLens\Catalog\PoolerVerdict;
use Pushery\SQLens\Catalog\ReaderSession;

/**
 * Establishes whether the connection an audit reads through is multiplexed across server backends.
 *
 * ## Why this is not part of the catalog reader, and must not be
 *
 * A transaction pooler's whole guarantee is that everything inside ONE transaction reaches one
 * backend. {@see ReaderSession::read()} wraps its work in a transaction, so
 * a probe run in there would find a perfectly stable backend on a pooled connection every single
 * time — and report "direct" with complete confidence.
 *
 * That is why this contract takes the connection rather than the session, and why an implementation
 * runs its statements OUTSIDE any transaction. The seam exists because the correct answer is only
 * observable in the one place the rest of the catalog layer deliberately never operates.
 *
 * An implementation opens no connection of its own — it is handed the one the audit already built —
 * takes no lock, and writes nothing. Setting a custom, namespaced GUC on the session is the strongest
 * thing it does, and that is a session variable rather than anything in a database.
 */
interface PoolerReader
{
    /**
     * Read the pooling situation.
     *
     * Never throws. A probe that could not run is {@see PoolerVerdict::Undetermined}
     * carrying what it saw — an exception here would take down a run that could still have audited a
     * schema, and a schema is the same on every backend.
     */
    public function read(): PoolerReading;
}
