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

    /**
     * No migration SQL was captured at all — the run read a catalog.
     *
     * Not "read statically from the migration source": no path in this package does that.
     * `Subjects\CaptureMode`, the enum that decides how a run actually captures, has two cases and
     * neither is this one. What wears this label is the audit and security suites: they open a
     * database, read its catalog, and reason about no migration text whatsoever. It is a label, not a
     * choice, because a catalog run still has to say what it did.
     */
    case Static = 'static';
}
