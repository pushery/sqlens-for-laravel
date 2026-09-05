<?php

declare(strict_types=1);

namespace Pushery\SQLens\Audit;

use Pushery\SQLens\Catalog\Degradation\CatalogNotice;
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
 * What an AUDIT run reports about ITSELF — every id, in the one place that admits to them.
 *
 * The lint suite has had this shape since its first release ({@see RunnerNotice}), and the catalog's
 * gaps have their own ({@see CatalogNotice}). The audit's own
 * notices were the family that never got one: eighteen ids written as bare string literals inside
 * {@see AuditNotices}, in no registry, each shipping a documentation link with no page behind it.
 *
 * That is not a tidiness problem. `rule-registry.json` is the artifact a consumer reads to learn what
 * this package can emit, and the completeness guard reconciles the shipped pages against it. An id
 * that appears in neither is invisible to both: nothing notices the missing page, and nothing notices
 * the missing entry either.
 *
 * ## Every one of them is the same kind of statement
 *
 * Safety, at the capturable level, stable — the same axes the other two families carry, and for the
 * same reason. They describe the RUN rather than a schema, so there is nothing for those axes to vary
 * with, and naming them once here beats repeating them at eighteen construction sites.
 */
enum AuditNotice: string implements RunNotice
{
    use CarriesNoSeverity;
    use ReportsWhatTheRunObserved;

    /** The filters admitted no rule, so the run checked nothing. */
    case NoActiveRules = 'CAP.L0.NO_ACTIVE_RULES';

    /**
     * A registered amplifier did not answer, so the checks it brings did not run.
     *
     * Its own case rather than the lint route's, and the distinction is not bookkeeping: the
     * SENTENCE a reader sees is shared between the two routes, but the id says which run produced
     * it. A finding out of an audit carrying `LINT.SKIPPED.MISSING_TOOL` would be a false statement
     * of origin — to the reader, to the baseline that fingerprints it, and to anything that filters
     * a report by where a finding came from.
     */
    case MissingTool = 'CAP.L0.MISSING_TOOL';

    /** Several connections could be the one to audit, and nothing said which. */
    case InstanceAmbiguous = 'CAP.L0.INSTANCE_AMBIGUOUS';

    /** The connection offers several read hosts, and nothing said which. */
    case AmbiguousReadHosts = 'CAP.L0.AMBIGUOUS_READ_HOSTS';

    /** A host was pinned that this connection does not configure. */
    case UnofferedHost = 'CAP.L0.UNOFFERED_HOST';

    /** The server that answered is not the one that was pinned. */
    case PinnedHostDiverged = 'CAP.L0.PINNED_HOST_DIVERGED';

    /** The pin could not be checked against the server — unconfirmed, not contradicted. */
    case PinnedHostUnverified = 'CAP.L0.PINNED_HOST_UNVERIFIED';

    /** The server is not the one the configuration describes. */
    case InstanceDivergence = 'CAP.L0.INSTANCE_DIVERGENCE';

    /** The session is multiplexed across backends, so instance-wide facts do not hold. */
    case ConnectionPooled = 'CAP.L0.CONNECTION_POOLED';

    /** The connection could not be opened, so nothing was audited. */
    case ServerUnreachable = 'CAP.L0.SERVER_UNREACHABLE';

    /** The server's own configuration could not be read, so no baseline rule had a subject. */
    case SettingsUnreadable = 'CAP.L0.SETTINGS_UNREADABLE';

    /** A rule was not applied because of the server's version. */
    case RuleWithheldByVersion = 'CAP.L0.RULE_WITHHELD_BY_VERSION';

    /**
     * A rule that is still registered and no longer runs, because it was deprecated.
     *
     * Its sibling above reports a rule the SERVER cannot support. This one reports a rule THIS
     * PACKAGE retired — and the two are worth telling apart, because the reader's next move differs:
     * one waits for a server upgrade, the other adopts the successor.
     *
     * Without it a deprecation is invisible from the outside. The rule stops producing findings, the
     * report gets shorter, and every remaining finding is still true — which is exactly what a clean
     * run looks like. `GOVERNANCE.md` promises a deprecated rule "stops producing findings and says
     * so"; this id is the "says so".
     */
    case RuleWithheldByDeprecation = 'CAP.L0.RULE_WITHHELD_BY_DEPRECATION';

    /** This instance cannot answer what the rule asks. */
    case InstanceScopeUnanswerable = 'CAP.L0.INSTANCE_SCOPE_UNANSWERABLE';

    /** The ignore list names something that is not a rule id. */
    case InvalidIgnoreList = 'CAP.L0.INVALID_IGNORE_LIST';

    /** An ignore entry resolved and silenced nothing. */
    case OrphanedIgnore = 'CAP.L0.ORPHANED_IGNORE';

    /** `--ignore-baseline` was passed and there is no baseline to bypass. */
    case NoBaselineToIgnore = 'CAP.L0.NO_BASELINE_TO_IGNORE';

    /** The project looks multi-tenant and has not declared a tenancy mode. */
    case TenancyNotDeclared = 'CAP.L0.TENANCY_NOT_DECLARED';

    /** Tenancy is explicit and no reference tenant is named. */
    case TenancyReferenceMissing = 'CAP.L0.TENANCY_REFERENCE_MISSING';

    /** The pinned server version and the server that answered disagree. */
    case AssumedVersionSkew = 'CAP.L0.ASSUMED_VERSION_SKEW';

    /** The instance that answered is below the floor the driver's rules were written for. */
    case ServerBelowFloor = 'CAP.L0.SERVER_BELOW_FLOOR';

    /** The engine that answered is not the engine the connection's driver key names. */
    case UnsupportedEngine = 'CAP.L0.UNSUPPORTED_ENGINE';

    /** The prefix every audit-run notice reports under — the run, not a rule. */
    public const string MESSAGE_PREFIX = 'sqlens.audit';

    public function id(): string
    {
        return $this->value;
    }

    public function messagePrefix(): string
    {
        return self::MESSAGE_PREFIX;
    }

    public function documentationUrl(): string
    {
        return RuleDocumentationUrl::for($this->value);
    }

    /**
     * None of these is a family: each names one exact id.
     *
     * The catalog's `AUDIT.CATALOG.UNREAD.<reason>` is the audit's family notice and lives with the
     * catalog's degradation vocabulary, where the reasons it varies over are defined.
     */
    public function coversFamily(): bool
    {
        return false;
    }

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

    public function suites(): array
    {
        return [Suite::Audit];
    }
}
