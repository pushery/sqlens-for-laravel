<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting;

/**
 * How SQLens obtained the SQL it reasons about. Part of the reproducibility header
 * because the same migration can produce different findings depending on how it was
 * captured, so a run's mode must be visible in its output.
 */
enum CaptureMode: string
{
    /** Laravel's `--pretend`: the SQL is collected without executing it. */
    case Pretend = 'pretend';

    /** Executed against a throwaway shadow database and read back from the catalog. */
    case Shadow = 'shadow';

    /** Read statically from the migration source, without a database. */
    case Static = 'static';
}
