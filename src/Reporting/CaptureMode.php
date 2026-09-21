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
     * ⚠️ THIS SAID "read statically from the migration source, without a database", and no path in
     * this package does that. `Subjects\CaptureMode`, the enum that decides how a run actually
     * captures, has two cases and neither is this one. What wears this label is the audit and
     * security suites: they open a database, read its catalog, and reason about no migration text
     * whatsoever — the opposite of the sentence that used to stand here.
     *
     * The description mattered because `sqlens.mode` offered this value as a CHOICE, so a project
     * could configure a capture strategy that does not exist. That key is gone; the label stays,
     * because a catalog run still has to say what it did.
     */
    case Static = 'static';
}
