<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Today;

/**
 * A driver that wants the run's day handed to it rather than reading a clock of its own.
 *
 * ## Why this is a separate interface and not a parameter on `Driver::rules()`
 *
 * Because `rules()` carries two jobs and only one of them knows a day. Measured over its callers:
 *
 *     src/Lint/LintRunner.php          judges a database   <- has a run
 *     src/Drivers/DriverManager.php    judges a database   <- has a run
 *     src/Catalog/RuleRegistryExport.php   enumerates rules
 *     src/Deploy/FindingEscalation.php     enumerates rules
 *
 * The last two build artifacts out of the rule set. Neither judges a database, neither has a
 * "today", and a required parameter would force both to invent one — a fabricated date inside an
 * artifact that is compared against a golden file is a non-deterministic artifact.
 *
 * And an optional parameter does not help in PHP. `rules(): iterable` takes none, so a parameter
 * added to the interface method breaks every implementer, default or not.
 * `DriverRegistry::extend()` exists precisely so that third-party implementers are a thing this
 * package has.
 *
 * ## What a driver that does not implement this gets
 *
 * The documented fallback: `SecurityRuleSet::forProjectRoot()` resolves the day itself when none is
 * handed over, once per `rules()` call. So a third-party driver keeps working unchanged and is not
 * silently degraded — it simply reads its own day, one reading per run of its own rules.
 *
 * A third-party driver does not fail here at all. Under a required parameter it would fail loudly,
 * which is better than silence and still a failure.
 */
interface AcceptsRunClock
{
    /**
     * A copy of this driver that hands the run's day to the rules it builds.
     *
     * Returns a new instance rather than mutating: a driver is resolved from a registry that other
     * runs share, and a run that set a day on the shared instance would leak it into the next one —
     * which is the container-singleton staleness {@see Today} exists to end, arriving one layer up.
     */
    public function withRunClock(Today $today): static;
}
