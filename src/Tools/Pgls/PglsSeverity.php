<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Pgls;

/**
 * The severities the Postgres Language Server's schema linter attaches to a rule.
 *
 * A CLOSED set, and measured rather than assumed: these three are what the 0.25.7 catalog
 * actually carries. That matters because the alternative — accepting whatever word arrives and
 * defaulting the unrecognized ones to something harmless — is how a tool that started emitting a
 * fourth level would have every finding at that level quietly filed as the mildest one. An
 * unknown severity is a report this adapter has not been written to read, which is exactly when
 * it should say so instead of guessing.
 *
 * These are the TOOL's words, deliberately not SQLens severities. Translating them is the finding
 * mapper's job, and keeping the two vocabularies apart is what stops a rename on either side from
 * silently reclassifying the other.
 */
enum PglsSeverity: string
{
    case Error = 'ERROR';

    case Warn = 'WARN';

    case Info = 'INFO';

    /** The set, spelled for an error message that has to say what WAS allowed. */
    public static function names(): string
    {
        return implode(', ', array_column(self::cases(), 'value'));
    }
}
