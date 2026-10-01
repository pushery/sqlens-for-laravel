<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Console\ExitCode;

/**
 * What decided a predeploy verdict, of the few things that can.
 *
 * Named rather than read off an exit code, because two of them share one: a failing check and a
 * finding about a pending migration both stop the deploy with the same code, and the sentence a
 * reader gets has to say which of the two it was.
 */
enum PreflightBlocker: string
{
    /** Nothing held the deploy back. */
    case Nothing = 'nothing';

    /** Only answers that could not be given held it back, and a waiver covered every one of them. */
    case Waived = 'waived';

    /** Only answers that could not be given held it back, and no waiver covered all of them. */
    case Unanswered = 'unanswered';

    /** A check about the instance found a real problem. */
    case CheckFailed = 'check_failed';

    /** A finding about a pending migration crossed the profile's gate. */
    case MigrationFinding = 'migration_finding';

    /** The run could not happen, so nothing about the deploy was established. */
    case Refused = 'refused';

    /** Baseline entries matched nothing, and `sqlens.baseline.stale` treats that as a misconfiguration. */
    case StaleBaseline = 'stale_baseline';

    public function exitCode(): ExitCode
    {
        return match ($this) {
            self::Nothing, self::Waived => ExitCode::Clean,
            self::Unanswered => ExitCode::UndeterminedInStrictMode,
            self::CheckFailed, self::MigrationFinding => ExitCode::FindingsAboveGate,
            self::Refused, self::StaleBaseline => ExitCode::Misconfiguration,
        };
    }
}
