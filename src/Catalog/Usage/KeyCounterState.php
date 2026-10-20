<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Usage;

/**
 * What a reading could say about the counter that feeds one primary key.
 *
 * Four answers rather than a number or nothing, because a rule that confused any two of them would
 * either call a key full on no evidence or say nothing about a key nobody was able to look at.
 */
enum KeyCounterState: string
{
    /** The counter was read, and it has handed out at least one value. */
    case Read = 'read';

    /** The counter was read, and it has not handed out a value yet. */
    case Unused = 'unused';

    /**
     * The counter exists, and the reading role may not see its position.
     *
     * On PostgreSQL that is a role holding neither SELECT nor USAGE on the sequence, which is where
     * `pg_monitor` stands on every sequence it was not granted. Kept apart from {@see self::Unused}
     * although the server answers both with NULL: only the privilege tells them apart, and one of
     * them is a fact about the key while the other is a fact about the role.
     */
    case Withheld = 'withheld';

    /** The counter exists, and reading its position failed. */
    case Unread = 'unread';
}
