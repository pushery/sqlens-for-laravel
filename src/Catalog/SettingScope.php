<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

/**
 * Whose value a setting is — the server's, or this connection's.
 *
 * Two cases and no third, because the distinction is binary and load-bearing: a rule about a
 * server's configuration must never be answered with a value that belongs to the audit's own
 * session. Behind a transaction pooler a session value may not even belong to the audit — measured
 * on PgBouncer, one client's `SET` is visible to another sharing the backend — which is why the
 * scope travels with every value instead of being assumed from the query that fetched it.
 */
enum SettingScope: string
{
    /** The server's own value: what a new connection would see. */
    case Global = 'global';

    /** This session's value, which may have been set by us — or, behind a pooler, by somebody else. */
    case Session = 'session';
}
