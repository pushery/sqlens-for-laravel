<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

/**
 * The exit-code contract every deploy script and CI pipeline wires against. It is
 * public API from 1.0 on: a later renumbering is a breaking change, so the MEANING
 * is fixed here, not just the value.
 *
 * The values stay within 0–255 and avoid clashing with Symfony's own reservations
 * where the meaning would differ: 0/1/2 keep Symfony's success/failure/misuse sense
 * (clean / findings / misconfiguration), and 3 is the first free value, used for the
 * one state a two-valued world cannot express — undetermined escalated by strict
 * mode. (Verified in the console spike; anything over 255 is clamped by Symfony.)
 */
enum ExitCode: int
{
    case Clean = 0;

    case FindingsAboveGate = 1;

    case Misconfiguration = 2;

    case UndeterminedInStrictMode = 3;

    /** A one-line English description — the source for the docs and `--help`. */
    public function description(): string
    {
        return match ($this) {
            self::Clean => 'No finding breached a gate; the run is clean.',
            self::FindingsAboveGate => 'One or more findings breached the level or severity gate.',
            self::Misconfiguration => 'The configuration is invalid; nothing was audited.',
            self::UndeterminedInStrictMode => 'A check was undetermined and strict mode escalated it to a failure.',
        };
    }
}
