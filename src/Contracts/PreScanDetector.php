<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Capture\CaptureRuleMetadata;
use Pushery\SQLens\Capture\PreScan\PreScanHit;
use Pushery\SQLens\Capture\PreScan\ScannedMigration;

/**
 * One pattern the static pre-scan looks for in a migration.
 *
 * Detectors read the ALREADY parsed and resolved migration; none of them parses,
 * and none of them walks the tree for itself. That keeps the pre-scan at one
 * traversal regardless of how many patterns it grows, which is what lets it sit
 * in front of the sub-second fast path.
 *
 * A detector reports hits; it never decides what happens next. Turning hits into
 * an `undetermined` result — and, crucially, into a migration that is NOT
 * pretend-executed — is the gate's job, deliberately separate: a detector that
 * could also suppress execution would make "found something" and "prevented
 * something" the same code path, and only one of them is a detection concern.
 *
 * There is no separate `ruleId()`: the id lives in the metadata and nowhere else,
 * so the id a report shows and the id the generated documentation lists cannot
 * drift apart.
 */
interface PreScanDetector
{
    /**
     * The published metadata of this detector — id, category, level, message
     * prefix, documentation URL, version window, stability, suites. The same
     * surface a rule carries, on a finding kind that is not a rule.
     */
    public function metadata(): CaptureRuleMetadata;

    /**
     * Every hit in this migration, in the order they appear in the file.
     *
     * @return list<PreScanHit>
     */
    public function detect(ScannedMigration $migration): array;
}
