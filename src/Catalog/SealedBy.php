<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

/**
 * What a reader session's read-only guarantee rests on, as its own write probe proved it.
 *
 * Every catalog reading opens with a write that must be refused, and the refusal names its cause:
 * the session refused it because it sealed itself read-only, or the account refused it because it
 * holds no write privilege. Both prove the reading could not write. They differ in what carries the
 * promise. The first rests on this package applying its seal; the second rests on the database's
 * grants, which a reviewer can check without trusting any code here.
 *
 * The value names the refusal the probe actually received, and an engine decides which check it
 * applies first. PostgreSQL refuses any DDL in a read-only transaction before it looks at a grant,
 * so an account without write privilege still reads as {@see self::Session} there. MySQL checks the
 * grant first, so the same account reads as {@see self::Privilege}.
 *
 * A session that has not read yet has proven neither, so it has no value at all rather than a
 * default: a header naming a seal no probe established would be a promise without cover.
 */
enum SealedBy: string
{
    /** The session's own read-only flag refused the probe. */
    case Session = 'session';

    /** The account's grants refused the probe: it may not write, whatever the session flag says. */
    case Privilege = 'privilege';
}
