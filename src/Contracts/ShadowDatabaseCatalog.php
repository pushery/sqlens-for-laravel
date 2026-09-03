<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Capture\Shadow\ShadowOrphanSweeper;

/**
 * The minimal per-driver catalog the orphan sweep needs: list the databases that
 * carry a given prefix, and drop one by name.
 *
 * It is a narrow port so the neutral {@see ShadowOrphanSweeper}
 * can find and remove leaked shadow databases without knowing how any engine spells
 * "list schemata" or "drop database" — the same core+driver split the rest of the
 * shadow path keeps. Both driver maintenance gateways implement it.
 *
 * Listing is deliberately BY PREFIX: the sweep only ever sees databases carrying the
 * shadow prefix, so it can never list — let alone drop — a database that is not the
 * tool's own. That is the first half of "never touch a database we did not create";
 * the sweeper's age check is the second.
 */
interface ShadowDatabaseCatalog
{
    /**
     * The names of existing databases whose name starts with $prefix, sorted.
     *
     * The ORDER IS PART OF THE CONTRACT. Neither `pg_database` nor
     * `information_schema.schemata` promises one, and the sweep report built from this
     * list is something a user reads — a run that reports the same two databases in a
     * different order every time contradicts the determinism this package is built on.
     * It also fails intermittently in a way that reads as a real defect: measured on a
     * live PostgreSQL, the same two leaked databases came back clone-then-template on
     * one run and template-then-clone on the next.
     *
     * @return list<string>
     */
    public function listDatabasesWithPrefix(string $prefix): array;

    /**
     * Drop $name idempotently — a name already gone is not an error, so a sweep that
     * races another cleanup does not fail.
     */
    public function dropDatabase(string $name): void;
}
