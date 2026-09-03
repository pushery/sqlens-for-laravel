<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting;

/**
 * The environment profile a run was executed under. It presets strictness and
 * which suites run, and it appears in the reproducibility header so a reader knows
 * whether a result came from a lenient local run or a strict pre-deploy gate.
 */
enum RunProfile: string
{
    case Local = 'local';

    case Ci = 'ci';

    case Predeploy = 'predeploy';
}
