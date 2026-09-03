<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

/**
 * What a run LOST when `auto` had to pass a backend over, said in the two forms a reader needs.
 *
 * ## Why a loss is reported at all when the run succeeded
 *
 * Falling back to the built-in core is correct — it is why the core exists, and a formatter that
 * refused to run without an optional binary would be useless on a fresh checkout. What is NOT
 * correct is doing it quietly: a machine without pgFormatter formats with something else than the
 * machine that has it, the output is COMMITTED, and the next run on the other machine rewrites
 * every file. Until this existed, nothing in a run said which of the two you were on.
 *
 * ## The ID is stable, and it is English
 *
 * `TOOL.PGFORMATTER.MISSING` and `TOOL.SQLFLUFF.MISSING` are the identifiers the acceptance
 * criteria name, and identifiers are public surface: they land in CI output people grep for. The
 * sentence beside each one may be improved; the ID may not change.
 */
final class BackendDegradation
{
    /**
     * The stable finding ID for a backend `auto` could not use.
     *
     * Built from the name rather than listed, so a backend added to {@see FormatterRegistry} cannot
     * arrive without one — a hand-written map is exactly the kind that goes one entry stale and
     * reports nothing for the newest member while looking complete.
     */
    public static function id(string $backend): string
    {
        return 'TOOL.'.strtoupper($backend).'.MISSING';
    }

    /**
     * One line saying what installing it would buy — the "what it would have brought" a degradation
     * is worthless without.
     *
     * A reader who is told only that something is missing has to go and find out whether they care.
     * A default rather than a match arm for an unknown name: a project may register its own backend,
     * and a run that threw on one would punish the extension seam for being used.
     */
    public static function whatItEnables(string $backend): string
    {
        return match ($backend) {
            'pgformatter' => 'the best available PostgreSQL formatting, including layouts the built-in core does not attempt',
            'sqlfluff' => 'a formatter that covers PostgreSQL and MySQL alike, and honors a project\'s own .sqlfluff',
            default => 'formatting from a backend this project preferred over the built-in core',
        };
    }
}
