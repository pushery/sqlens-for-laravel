<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Security\Advisory\PatchAssessment;
use Pushery\SQLens\Security\Advisory\PatchVerdict;
use Pushery\SQLens\Severity\Severity;

/**
 * The server is running a release series whose support window has closed.
 *
 * `high`, and the reasoning is about what happens NEXT rather than about anything measurable today.
 * An out-of-support server is not insecure the moment support ends — it is a server that will not
 * receive the fix for the next vulnerability found in it, and the interval between a fix existing
 * for supported versions and an exploit existing for unsupported ones is measured in days. The
 * finding is therefore about a countdown that has already started, which is why it does not wait
 * for a CVE to name.
 *
 * Not `critical`: nothing here is known to be exploitable, and reserving the top weight for
 * demonstrated exposure is what keeps it meaningful. A team that has to plan a major upgrade needs
 * to know it is overdue, not to be told the building is on fire.
 */
final class PatchEolRule extends AbstractPatchLevelRule
{
    public function id(): string
    {
        return 'SEC.CFG.PATCH_EOL';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    protected function judges(PatchVerdict $verdict): bool
    {
        // Only the verdicts that answer THIS rule's question, which is "is the series in support?".
        //
        // `PatchLevelUnknown` is deliberately not among them, and that is the difference between an
        // honest silence and a noisy one. When the data records no patch level, the support question
        // still got a real answer — the series runs until its recorded date — and reporting an
        // undetermined here would attach "could not check" to a check that succeeded. Worse, the
        // bundled file records no patch level for ANY cycle, so it would be an undetermined on every
        // audit run this package ever performs: under `strict_undetermined` that is a permanently
        // red pipeline, and a signal that fires always is a signal nobody reads.
        //
        // The two that remain are real failures to answer: a cycle this data has never heard of, and
        // a version string nothing could parse. Neither is "in support" and neither is "not".
        return in_array($verdict, [PatchVerdict::Ended, PatchVerdict::CycleUnknown, PatchVerdict::VersionUnparsable], true);
    }

    protected function flag(PatchAssessment $assessment): string
    {
        return sprintf(
            'the server reports %s, and support for the %s series ended on %s. What that costs is not '
            .'visible today: the server is not newly broken, it is simply no longer on the list that '
            .'receives the fix for the next vulnerability found in it — and the gap between a patch '
            .'existing for supported versions and an exploit existing for the rest is days, not '
            .'quarters. Plan the major upgrade; there is no configuration change that substitutes for '
            .'it. %s (%s).',
            $assessment->reported,
            (string) $assessment->cycle,
            (string) $assessment->entry?->eolDate,
            (string) $assessment->entry?->note,
            $assessment->provenance(),
        );
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'compares a version against shipped end-of-life data, so it is only as current as that data. A series whose support window closed after this package\'s copy was written is not reported until the data is refreshed — which is why the artifact carries its own age',
            'a vendor-supported build can outlive its upstream series. A distribution or managed provider backporting fixes is not visible in a version banner, and this rule reads the banner',
        ];
    }
}
