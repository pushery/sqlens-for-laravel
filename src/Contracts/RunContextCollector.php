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
     * @param  CaptureMode  $mode  how THIS run obtained the SQL it reasons about
     *
     * ⚠️ REQUIRED, and it used to be read from `sqlens.mode` instead. A configuration key cannot
     * answer this question: the same installation runs `sqlens:lint` in pretend, `sqlens:drift`
     * against a shadow replay and `sqlens:audit` over a catalog, and the header then announced
     * whatever the file said for all three. Every producer already knows its own answer — each
     * builds a `RunMetadata` carrying it, with a written reason — so the two came from different
     * places and disagreed in the same document.
     */
    public function collect(CaptureMode $mode): RunContext;
}
