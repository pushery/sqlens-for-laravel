<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Degradation;

use Pushery\SQLens\Catalog\SkipReason;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\CarriesNoSeverity;
use Pushery\SQLens\Contracts\ReportsWhatTheRunObserved;
use Pushery\SQLens\Contracts\RunNotice;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Lint\RunnerNotice;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Rules\Suite;

/**
 * What an AUDIT run reports about its own reading of the catalog.
 *
 * The lint runner already has this shape ({@see RunnerNotice}) for "the run
 * could not lint anything". The audit suite needs the same thing for "the reading was not a
 * complete statement about this database", and it is a run-level fact rather than a rule's finding:
 * no statement was judged, and no rule was wrong.
 *
 * ## One family, one page
 *
 * A concrete notice reports as `AUDIT.CATALOG.UNREAD.<reason>` — the {@see SkipReason} that names
 * the gap. Every one of them shares one page, because what a reader needs to know is the same in
 * all of them: an audit can come back incomplete, and an incomplete audit is not a clean one. A page
 * per reason would be the same sentence written seven times and maintained none.
 *
 * ## …and the one reason that is not a gap gets an id of its own
 *
 * `not_comparable` names an object that was read completely and lies outside a comparison on
 * purpose. Filed under `UNREAD` it would say the opposite of what it means, which is the confusion
 * that made the reason necessary: a consumer read correct, deliberate boundaries as a backlog. So it
 * reports as `AUDIT.CATALOG.NOT_COMPARED`, a single id with its own page, and as not_applicable
 * rather than undetermined.
 */
enum CatalogNotice: string implements RunNotice
{
    use CarriesNoSeverity;
    use ReportsWhatTheRunObserved;

    /** The family page for `AUDIT.CATALOG.UNREAD.<reason>` — something in scope went unread. */
    case CatalogUnread = 'AUDIT.CATALOG.UNREAD';

    /** An object read completely and left out of a comparison by design — one id, one page. */
    case CatalogNotCompared = 'AUDIT.CATALOG.NOT_COMPARED';

    /** The prefix these report under — the audit run, not a rule. */
    public const string MESSAGE_PREFIX = 'sqlens.audit';

    /** The concrete id for one skip: the family and the reason for a gap, the single id for a boundary. */
    public static function idFor(SkipReason $reason): string
    {
        if ($reason === SkipReason::NotComparable) {
            return self::CatalogNotCompared->value;
        }

        return self::CatalogUnread->value.'.'.mb_strtoupper($reason->value);
    }

    /** The page for the notice a skip with this reason reports under. */
    public static function forReason(SkipReason $reason): self
    {
        return $reason === SkipReason::NotComparable ? self::CatalogNotCompared : self::CatalogUnread;
    }

    public function id(): string
    {
        return $this->value;
    }

    public function messagePrefix(): string
    {
        return self::MESSAGE_PREFIX;
    }

    public function coversFamily(): bool
    {
        return $this === self::CatalogUnread;
    }

    /**
     * Safety, at the capturable level, stable — the same axes the lint runner's notices carry, and
     * for the same reason: they describe the RUN, so there is nothing for these axes to vary with.
     */
    public function category(): Category
    {
        return Category::Safety;
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    public function stability(): StabilityTier
    {
        return StabilityTier::Stable;
    }

    public function documentationUrl(): string
    {
        return RuleDocumentationUrl::for($this->value);
    }

    public function suites(): array
    {
        return [Suite::Audit];
    }
}
