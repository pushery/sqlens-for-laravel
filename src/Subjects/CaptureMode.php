<?php

declare(strict_types=1);

namespace Pushery\SQLens\Subjects;

/**
 * How the migration SQL was captured. A pretend run is a simulation, not truth:
 * rules may judge more cautiously when the SQL was only simulated, so this is a
 * required field — a pretend result can never be silently read as ground truth.
 */
enum CaptureMode: string
{
    case Pretend = 'pretend';
    case Shadow = 'shadow';
}
