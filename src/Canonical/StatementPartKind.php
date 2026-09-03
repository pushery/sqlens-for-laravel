<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

/**
 * What one piece of a split batch IS — and the reason splitting returns a kind at all.
 *
 * A batch read from a hand-written `.sql` file holds two different things. Most of it is SQL the
 * server executes. Some of it is addressed to the CLIENT — `\i other.sql`, `\set ON_ERROR_STOP on` —
 * and the server never sees those lines at all. They are not statements, they do not end at a
 * semicolon, and a consumer that treats one as SQL is holding something the parser will never
 * accept.
 *
 * Handing both back as plain strings would make that distinction a guess at every call site. The
 * kind makes it a property.
 */
enum StatementPartKind: string
{
    /** Something the server executes. */
    case Sql = 'sql';

    /**
     * A client directive: a line the SQL client interprets and the server never receives.
     *
     * `psql`'s backslash commands are the only instance today. It is a KIND rather than a driver
     * name because the property that matters downstream is "not SQL", not "PostgreSQL".
     */
    case ClientDirective = 'client_directive';
}
