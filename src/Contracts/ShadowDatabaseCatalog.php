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
     * The names of existing databases whose name starts with $prefix.
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
