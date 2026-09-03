<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan;

use Pushery\SQLens\Contracts\PreScanDetector;
use Pushery\SQLens\Rules\RuleIdFormat;
use Pushery\SQLens\Rules\RuleMetadataAudit;
use Pushery\SQLens\Rules\Suite;

/**
 * The metadata fence for pre-scan detectors — the rule audit's twin for the one
 * finding kind that is not a rule.
 *
 * It reuses `RuleMetadataAudit::fieldViolations()` for the shared invariants, so
 * "complete metadata" has exactly one definition, and adds the three that are
 * specific to a pre-scan hit:
 *
 * - the id belongs to the reserved `CAP.PRESCAN.*` family, so a pre-scan hit can
 *   never be mistaken for a leveled rule in a baseline or an ignore list;
 * - a null downtime class carries a written rationale, so "no DDL to classify"
 *   is distinguishable from a field somebody forgot;
 * - the detector names at least one suite, because a detector belonging to no
 *   suite runs nowhere and would be a silent no-op.
 */
final class PreScanMetadataAudit
{
    /**
     * Every metadata violation across the given detectors, plus any duplicate id.
     * An empty list means all of them are well-formed.
     *
     * @param  iterable<PreScanDetector>  $detectors
     * @return list<string>
     */
    public static function violations(iterable $detectors): array
    {
        $violations = [];
        $seen = [];

        foreach ($detectors as $detector) {
            $metadata = $detector->metadata();
            $id = $metadata->id;

            foreach (RuleMetadataAudit::fieldViolations(
                'pre-scan detector',
                $id,
                $metadata->category,
                $metadata->severity,
                $metadata->messagePrefix,
                $metadata->documentationUrl,
            ) as $violation) {
                $violations[] = $violation;
            }

            if (! RuleIdFormat::isPreScan($id)) {
                $violations[] = sprintf('pre-scan detector "%s" is outside the reserved CAP.PRESCAN.* family', $id);
            }

            if ($metadata->downtimeClass === null && trim($metadata->downtimeClassRationale) === '') {
                $violations[] = sprintf('pre-scan detector "%s" declares no downtime class and no rationale for its absence', $id);
            }

            if ($metadata->suites === []) {
                $violations[] = sprintf('pre-scan detector "%s" belongs to no suite, so it would never run', $id);
            }

            if (in_array($id, $seen, true)) {
                $violations[] = sprintf('pre-scan detector id "%s" is declared twice', $id);
            }

            $seen[] = $id;
        }

        return $violations;
    }

    /**
     * The suite every pre-scan detector runs in. The pre-scan is what makes the
     * lint suite's level-0 assurance ("the SQL is capturable") answerable at all,
     * so it is lint's, and a later suite that wants it adds itself here rather
     * than each detector guessing.
     *
     * @return list<Suite>
     */
    public static function defaultSuites(): array
    {
        return [Suite::Lint];
    }
}
