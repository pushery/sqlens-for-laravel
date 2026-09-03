<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Reporting\RunContext;

/**
 * Collects the parameters of the current run into a RunContext. The seam exists so
 * a later collector can swap the trivial config-only one for one that probes
 * real server versions and discovers external tool versions, without any reporter
 * changing — a reporter depends on this contract, never on how the context is built.
 */
interface RunContextCollector
{
    public function collect(): RunContext;
}
