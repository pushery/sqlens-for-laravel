<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

/**
 * Which SQL dialect a formatter is being asked to format for.
 *
 * ## An enum and not a driver object, deliberately
 *
 * Formatting needs to know that `\`orders\`` is a MySQL identifier and `"orders"` a PostgreSQL one.
 * That is the whole of it — no catalog, no connection, no rules. Taking a driver here would pull the
 * entire driver hierarchy into `src/Format/`, and an architecture test would then have to allow what
 * every other part of this package forbids: a namespace that reaches into both engines.
 *
 * The value comes IN. Resolving `auto` to one of these is somebody else's job, one layer up, where a
 * connection exists to ask.
 *
 * Two cases and no third. MariaDB, SQLite and SQL Server are declared non-goals for this package,
 * and a formatter that offered them would be the one place claiming otherwise.
 */
enum Dialect: string
{
    case Pgsql = 'pgsql';
    case Mysql = 'mysql';
}
