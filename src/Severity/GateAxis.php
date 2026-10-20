<?php

declare(strict_types=1);

namespace Pushery\SQLens\Severity;

use Pushery\SQLens\Categories\Category;

/**
 * The two orthogonal gates a finding can be measured against.
 *
 * It lives beside the gates rather than beside the reporters, and the direction is the point: a
 * gate decides, a reporter reads the decision. With this enum under `Reporting\Summary` the
 * decision object would have had to import from the layer that renders it. They are not
 * interchangeable: the level gate models the strictness appetite (which rules a run
 * asked for), the severity gate models risk. A security or privacy finding is gated
 * only by severity — a level-2 run still breaks on a critical security finding — so
 * a summed total without provenance hides exactly the thing a reader needs.
 */
enum GateAxis: string
{
    case Level = 'level';

    case Severity = 'severity';

    /**
     * Which gate a finding of the given category is measured against, by the one answer
     * {@see Category::usesSeverityGate()} gives, which the level gate admits by as well.
     */
    public static function forCategory(Category $category): self
    {
        return $category->usesSeverityGate() ? self::Severity : self::Level;
    }
}
