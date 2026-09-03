<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Severity\Severity;

/**
 * The answer for a notice family whose findings carry no severity.
 *
 * Most run notices describe what the RUN could do — "no active rules matched", "the catalog could
 * not be read" — and a severity would be inventing an axis they do not have. They say so here, once,
 * rather than in forty-odd enum cases.
 *
 * A family that uses this trait is making a CLAIM, not taking a shortcut: it is stating that none of
 * its members carries a severity. When one starts to, the trait comes off and the family answers per
 * case — which is exactly what `DebtNotice` does.
 */
trait CarriesNoSeverity
{
    public function severity(): ?Severity
    {
        return null;
    }
}
