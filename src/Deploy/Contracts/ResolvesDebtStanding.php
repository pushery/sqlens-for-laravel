<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Contracts;

use Pushery\SQLens\Deploy\DebtEntry;
use Pushery\SQLens\Deploy\DebtStanding;

/**
 * What the live catalog says about one recorded debt.
 *
 * ## Why this is a contract and not a method on the collector
 *
 * The question is engine-specific — `pg_constraint.convalidated`, `pg_index.indisvalid`,
 * `information_schema` — and the collector is core. A collector that knew how to ask would be the
 * driver knowledge the purity census keeps out of the core, and it would have to grow a branch per
 * debt kind per engine in the one class that is supposed to be about arithmetic.
 *
 * ## What an implementation must NOT do
 *
 * It must not re-derive a debt this package already reads elsewhere. The catalog columns that say
 * whether a constraint is validated or an index is valid each have exactly one reader, and a second
 * one is the same database answering differently depending on which command asked. An
 * implementation asks about the OBJECT — is it there at all — and delegates the debt question to
 * the check that owns it.
 *
 * And it reads only. State and catalog views, its own session bounds, never a lock of its own.
 */
interface ResolvesDebtStanding
{
    /**
     * Where one recorded debt stands, live.
     *
     * Every path must answer. {@see DebtStanding::ObjectNotFound} is the answer for "I could not
     * find out", and it is deliberately not a resolution — a caller that received a definite answer
     * has one because this method could give one, never because it ran out of ways to look.
     */
    public function standingFor(DebtEntry $entry): DebtStanding;
}
