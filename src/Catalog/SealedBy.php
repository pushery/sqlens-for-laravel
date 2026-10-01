<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

/**
 * What a reader session's read-only guarantee rests on, as its own write probe proved it.
 *
 * Every catalog reading opens with a write that must be refused. When the session's seal refused
 * it, the seal is proven by that refusal. When a privilege refused it, the refusal proves only that
 * the account may not create the probe's temporary table, so two readings decide instead: the
 * account's own grants, and the transaction's read-only flag as the server reports it. Both values
 * mean the reading could not write. They differ in what carries the promise. The first rests on
 * this package applying its seal; the second rests on the database's grants, which a reviewer can
 * check without trusting any code here.
 *
 * An engine decides which check it applies first. PostgreSQL refuses any DDL in a read-only
 * transaction before it looks at a grant, so every account reads as {@see self::Session} there.
 * MySQL checks the grant first, so an account without the temporary-table right reads as
 * {@see self::Privilege} when its grants name nothing but reading privileges, and as
 * {@see self::Session} when they name anything more and the flag is on.
 *
 * A session that has not read yet has proven neither, so it has no value at all rather than a
 * default: a header naming a seal no probe established would be a promise without cover.
 */
enum SealedBy: string
{
    /** The session's own read-only flag holds: it refused the probe, or the server reported it on. */
    case Session = 'session';

    /** The account's grants were read and name nothing but reading: it may not write, whatever the session flag says. */
    case Privilege = 'privilege';
}
