<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Reporting\CaptureMode;
use Pushery\SQLens\Reporting\RunContext;

/**
 * Collects the parameters of the current run into a RunContext. The seam exists so
 * a later collector can swap the trivial config-only one for one that probes
 * real server versions and discovers external tool versions, without any reporter
 * changing — a reporter depends on this contract, never on how the context is built.
 */
interface RunContextCollector
{
    /**
     * @param  CaptureMode  $mode  how this run obtained the SQL it reasons about
     *
     * Required, and never read from configuration. A configuration key cannot answer this
     * question: the same installation runs `sqlens:lint` in pretend, `sqlens:drift` against a shadow
     * replay and `sqlens:audit` over a catalog. Every producer knows its own answer, and this
     * parameter is the single place it goes.
     */
    public function collect(CaptureMode $mode): RunContext;
}
