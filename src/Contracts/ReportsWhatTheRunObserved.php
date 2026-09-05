<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

/**
 * The answer for a notice family that reports what the RUN observed, never what a reader wrote.
 *
 * Every run notice in this package is of that kind — "no active rules matched", "the catalog could
 * not be read", "the version pin is unreadable". They say so here, once, rather than in forty-odd
 * enum cases, exactly as {@see CarriesNoSeverity} does for the axis beside it.
 *
 * A family using this trait is making a CLAIM, not taking a shortcut: it states that none of its
 * members is caused by text the reader can rewrite. When one is, the trait comes off and the family
 * answers per case — the same escape `DebtNotice` took on severity.
 */
trait ReportsWhatTheRunObserved
{
    public function attribution(): Attribution
    {
        return Attribution::Observed;
    }
}
