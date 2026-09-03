<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Deploy\Contracts\ResolvesDebtStanding;
use Pushery\SQLens\Deploy\DebtStanding;

/**
 * Which catalog question a recorded debt gets, for the engine it lives on.
 *
 * The same shape and the same reason as {@see SessionDefenses}: the mapping is the one piece that
 * HAS to know both engines, and the core must not. `src/Audit` is scanned for engine vocabulary and
 * would fail with a concrete resolver imported, so the choice lives behind this interface and the
 * knowledge stays in `src/Drivers` — in the registry that already carries the other driver mappings,
 * because exactly three files in this package may know both engines and a fourth would grow the set
 * the purity census exists to bound.
 *
 * The method is not called `for()`, which was the first instinct. One class implements both
 * contracts and PHP has one method per name.
 *
 * It exists at all because the direct wiring works — until the second engine. A runner holding a
 * PostgreSQL resolver answers correctly today and answers PostgreSQL's question about a MySQL
 * database tomorrow, and the day that happens the driver knowledge is already in the core and the
 * fix is a rewrite rather than an entry.
 */
interface DebtStandingResolvers
{
    /**
     * The resolver for this driver.
     *
     * @param  list<string>  $stillOwed  the canonical object names this run's checks reported as
     *                                   still carrying their debt — the one reading of those
     *                                   catalog columns, taken by the classes that own them
     *
     * An engine this build has no resolver for gets one that answers
     * {@see DebtStanding::ObjectNotFound} to everything. That is the honest
     * answer rather than a convenient one: "this build cannot find out on this engine" and "the
     * object is not there" are both the question staying open, and both are reported with a named
     * reason. Returning null instead would make every caller invent its own handling, and one of
     * them would eventually invent silence.
     */
    public function debtStandingResolverFor(string $driver, array $stillOwed, ReaderSession $session): ResolvesDebtStanding;
}
