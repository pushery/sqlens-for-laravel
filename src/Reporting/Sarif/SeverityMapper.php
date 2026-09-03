<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Sarif;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Outcome;
use Pushery\SQLens\Severity\GateAxis;
use Pushery\SQLens\Severity\GateDecision;
use Pushery\SQLens\Severity\Severity;

/**
 * How a finding's weight reaches GitHub — and it is NOT through `level`.
 *
 * This is the part of a SARIF upload that is easy to get wrong in a way nobody notices. GitHub's
 * code-scanning UI sorts and filters alerts by **`security-severity`**, a numeric property in the
 * rule's `properties` bag. `level` only decides the icon. So a `critical` finding published with the
 * right `level` and no `security-severity` arrives as an alert with no weight at all — visible,
 * greyed, and below everything that did carry a number.
 *
 * ## The table is the single truth
 *
 * | SQLens severity | SARIF `level` | `security-severity` |
 * |---|---|---|
 * | critical | `error` | 9.0 |
 * | high | `error` | 7.0 |
 * | medium | `warning` | 5.0 |
 * | low | `warning` | 3.0 |
 * | info | `note` | 1.0 |
 *
 * Written as a `match` over the enum rather than as an array, so a sixth severity is a compile-time
 * failure here instead of a missing key that publishes an alert with no weight.
 *
 * ## Why the AXIS decides, not the presence of a severity
 *
 * A safety rule is explicitly allowed to declare a severity — `RuleMetadataAuditTest` has an arm for
 * it — and that severity does nothing, on purpose: the level gate is what measures a safety finding.
 * Reading `$finding->severity !== null` here would quietly hand such a rule a GitHub weight it was
 * never meant to carry, and put it above real security findings in a security tab.
 *
 * {@see GateAxis::forCategory()} is where that question is already answered, once, for the exit code
 * and the summary counts as well. This reads the same decision rather than re-deriving it — the same
 * argument the JSON envelope makes about `blocked_by`.
 *
 * ## Why `undetermined` is a note and not an error
 *
 * The instinct is the opposite: a critical risk nobody could rule out reads like a block. It does not
 * survive contact with a managed database, where the application's role cannot read `pg_authid`,
 * cannot read `pg_hba_file_rules` and cannot see half of `mysql.*` — nearly every security check
 * comes back unanswerable, so every upload would arrive as a wall of errors. Weight buys attention,
 * and attention that is always spent is attention nobody has left.
 *
 * Nothing is lost by it: the finding is still in the document, and `sqlens-state` names it as
 * undetermined so a consumer can filter on exactly that. What turns an unanswerable check into a
 * failing run is `strict_undetermined`, decided once per project — not this mapping, which only
 * decides how loudly the tab says it. The GitHub-annotations reporter reached the same conclusion for
 * the same reason.
 */
final readonly class SeverityMapper
{
    /** The property GitHub reads to weigh an alert. Spelled as GitHub spells it, hyphen included. */
    public const string SECURITY_SEVERITY = 'security-severity';

    /** The property that keeps a three-valued result three-valued once it is inside a two-valued tool. */
    public const string STATE = 'sqlens-state';

    /**
     * The SARIF level for one finding, measured against the run's own gates.
     *
     * The ladder is ordered so the earlier rungs cannot be overridden by the later ones, and each
     * order is a decision:
     *
     * 1. A pass or a structural not-applicable is `none` — SARIF's own value for "this does not
     *    indicate a problem". Carried rather than dropped, so the record stays complete while the tab
     *    stays quiet.
     * 2. An undetermined is a `note`, for the reason in the class docblock, whatever its severity.
     *    Placed ABOVE the severity rung deliberately: a critical check that could not run is still a
     *    check that did not run.
     * 3. A finding on the risk axis takes the table.
     * 4. Everything else takes the LEVEL gate — `error` when this run's level would block it,
     *    `warning` when the finding is real but below the threshold this run chose. That keeps the
     *    two axes visibly separate, which is the whole reason they exist.
     */
    public static function level(Finding $finding, GateDecision $decision): string
    {
        if ($finding->status->outcome === Outcome::Pass || $finding->status->outcome === Outcome::NotApplicable) {
            return 'none';
        }

        if ($finding->status->outcome === Outcome::Undetermined) {
            return 'note';
        }

        if ($decision->axis === GateAxis::Severity && $finding->severity instanceof Severity) {
            return self::forSeverity($finding->severity)['level'];
        }

        // Reached by a security rule that declares no severity as well as by every level-gated
        // finding. That first case is one `RuleMetadataAuditTest` forbids outright, so it cannot
        // ship — but a mapper that silently guessed a weight for it would make the audit's job
        // harder rather than easier. Falling to the level gate states what IS known.
        return $decision->blockedBy === GateAxis::Level ? 'error' : 'warning';
    }

    /**
     * The numeric weight GitHub sorts by, or null when this finding is not on the risk axis.
     *
     * Null and absent are the same thing here, unlike everywhere else in this package: SARIF's
     * `properties` bag has no schema, so an explicit null would be a property whose value is null —
     * and GitHub reads that as a weight it cannot parse rather than as an absence. The caller omits
     * the key.
     */
    public static function securitySeverity(Finding $finding, GateDecision $decision): ?string
    {
        if ($decision->axis !== GateAxis::Severity || ! $finding->severity instanceof Severity) {
            return null;
        }

        return self::forSeverity($finding->severity)['security_severity'];
    }

    /**
     * The table, in one place, as a total match over the enum.
     *
     * The numbers are GitHub's own bands rather than invented: it reads 9.0 and above as critical,
     * 7.0–8.9 as high, 4.0–6.9 as medium and below 4.0 as low. Picking the bottom of each band means
     * a severity lands where its name says it does — and a value one tenth lower would silently
     * demote every finding of that class.
     *
     * @return array{level: string, security_severity: string}
     */
    private static function forSeverity(Severity $severity): array
    {
        return match ($severity) {
            Severity::Critical => ['level' => 'error', 'security_severity' => '9.0'],
            Severity::High => ['level' => 'error', 'security_severity' => '7.0'],
            Severity::Medium => ['level' => 'warning', 'security_severity' => '5.0'],
            Severity::Low => ['level' => 'warning', 'security_severity' => '3.0'],
            Severity::Info => ['level' => 'note', 'security_severity' => '1.0'],
        };
    }
}
