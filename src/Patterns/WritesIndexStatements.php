<?php

declare(strict_types=1);

namespace Pushery\SQLens\Patterns;

use Pushery\SQLens\Contracts\Driver;

/**
 * The seam between the index advisor and the two drivers whose catalogs it reads: the driver writes the
 * statement that builds a suggested index without blocking writes.
 *
 * The statement's syntax belongs to the engine, and the core names no engine's vocabulary, so the
 * advisor decides the index and the driver writes it. It is no extension point: the advisor reads the
 * catalogs of `pgsql` and `mysql` only, and a key that is taken cannot be registered again.
 *
 * @internal
 */
interface WritesIndexStatements
{
    /** The key of the driver, the one {@see Driver::key()} answers. */
    public function key(): string;

    /**
     * The statement that builds the index.
     *
     * @param  string  $target  the quoted table, with its schema where the catalog names one
     * @param  string  $name  the quoted name of the index
     * @param  list<string>  $columns  the quoted columns, in the order of the index
     * @param  list<string>  $conditions  the quoted predicates of a partial index; only an engine that has partial indexes is given any
     */
    public function indexStatement(string $target, string $name, array $columns, array $conditions): string;
}
