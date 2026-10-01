<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

/**
 * Where a shadow capture leaves its sweep report for the run that reports it.
 *
 * The report cannot ride on the capture run. The shadow captor sits under decorators that each
 * build a new run from the results they pass on, and a field one of them forgot to carry would be
 * dropped without a sound, which is the silence this report exists to end. So the command that asks
 * for a shadow capture hands one of these in and reads it afterwards.
 */
final class ShadowSweepRecorder
{
    private ?ShadowSweepReport $report = null;

    /** Record a sweep, merged with any recorded before it, so a second sweep cannot hide the first. */
    public function record(ShadowSweepReport $report): void
    {
        $this->report = $this->report instanceof ShadowSweepReport ? $this->report->merge($report) : $report;
    }

    /** The sweep this run recorded, or null when none ran. */
    public function report(): ?ShadowSweepReport
    {
        return $this->report;
    }
}
