<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Catalog\SettingsReading;

/**
 * Reads a server's variables — the one place each engine's way of asking for them may live.
 *
 * `pg_settings` and `performance_schema` are engine vocabulary, and the core namespaces are kept
 * free of it. Every consumer that reasons about a server's configuration — the baseline rules here,
 * the security reader later — asks through this and never learns what answered.
 *
 * An implementation reads and nothing else: no lock, no write, no connection of its own. It is
 * handed the session the catalog reader already opened and sealed.
 */
interface ServerSettingsReader
{
    /**
     * Every setting this reader can see, plus whether the reading happened at all.
     *
     * A setting the server withheld is ABSENT rather than present with a guessed value. The
     * difference matters: a rule that found nothing for a name reports that it could not check,
     * while one handed a default that was never read would report a pass. PostgreSQL omits
     * superuser-only rows from `pg_settings` silently — measured — so the absent case is ordinary,
     * not exotic.
     *
     * A reading that FAILED is not the same as one that found nothing, and returning a bare map
     * would make them identical — an ambiguity that has already produced one wrong diagnosis.
     */
    public function read(): SettingsReading;
}
