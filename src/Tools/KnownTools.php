<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

/**
 * The tools SQLens knows how to lean on — Squawk and the Postgres Language Server today.
 *
 * The list is not written here. It is assembled by asking each registered DRIVER for its own
 * adapters, so a PostgreSQL-only tool ships with the PostgreSQL driver rather than being named by a
 * core composition root that could not autoload it.
 *
 * The rule that governs what may appear is unchanged, and it is the reason this docblock exists at
 * all: a tool is listed once it actually powers a rule, and not a moment sooner. Listing one earlier
 * turns "missing amplifier" into a promise with nothing behind it — which is the same silent loss of
 * coverage the strict-tool machinery was built to make loud.
 */
final readonly class KnownTools
{
    /** @param  list<Tool>  $tools */
    public function __construct(public array $tools = []) {}
}
