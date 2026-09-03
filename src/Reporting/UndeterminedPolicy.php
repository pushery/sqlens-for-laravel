<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Outcome;
use Pushery\SQLens\Findings\Result;

/**
 * Decides how a run's undetermined findings affect its gate: lenient in normal
 * mode, escalating under strict-undetermined. This is the origin of the
 * "undetermined in strict mode" exit status.
 *
 * Two invariants it must never break:
 *
 * - No silent green. A check that could not run is an undetermined with a named
 *   reason; this policy never turns one into a pass. That is guaranteed upstream by
 *   the type system (FindingStatus cannot be undetermined without a reason), and the
 *   policy only reads that state, never launders it away.
 * - No boolean collapse. An undetermined is a third class, not a `fail`. The verdict
 *   is an UndeterminedVerdict, not a bool, and it never relabels the underlying
 *   Outcome — a strict-mode block is reported as an escalated UNDETERMINED, distinct
 *   from a genuine fail, so a later exit-code mapping can tell them apart.
 *
 * The `--allow-undetermined` escape hatch (a pre-deploy override that tolerates
 * undetermined even under strict mode) is only a contract here — its wiring lands
 * with the deploy lifecycle, and this policy is where it will attach.
 */
final readonly class UndeterminedPolicy
{
    public function verdict(Result $result, RunContext $context): UndeterminedVerdict
    {
        if (! $this->hasUndetermined($result)) {
            return UndeterminedVerdict::None;
        }

        return $context->strictUndetermined
            ? UndeterminedVerdict::Escalated
            : UndeterminedVerdict::Tolerated;
    }

    private function hasUndetermined(Result $result): bool
    {
        return array_any($result->findings, fn (Finding $finding): bool => $finding->status->outcome === Outcome::Undetermined);
    }
}
