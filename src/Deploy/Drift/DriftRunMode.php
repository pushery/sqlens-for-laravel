<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

/**
 * Whether a drift run REPORTS or BLOCKS.
 *
 * The default is report, and that is a survival decision rather than a courtesy. The first drift
 * run on a grown production database finds a decade of hand-made objects, and a gate that turns red
 * on that first run is not adopted — it is switched off, after which nothing is reported at all.
 * The documented path is report first, then excludes, then gate.
 *
 * A green exit code in report mode is only defensible because the mode is printed in every output.
 * Without that line it would be the exact silent green this package refuses everywhere else: a
 * reader would see zero and believe it meant no drift.
 */
enum DriftRunMode: string
{
    /** Findings are printed in full and the run exits clean. */
    case Report = 'report';

    /** Findings end the run with the gate exit code. Reached only by asking for it. */
    case Gate = 'gate';

    /**
     * The mode a run should use, from the flag and the configured value.
     *
     * The flag wins, and only ever in the blocking direction: there is no way to reach the gate
     * without having named it, and no flag here that turns a configured gate back off. A project
     * that configured `gate` decided that once, deliberately; letting a command-line switch undo it
     * would make the strictest setting the easiest one to lose.
     */
    public static function resolve(bool $failOnDrift, mixed $configured): self
    {
        if ($failOnDrift) {
            return self::Gate;
        }

        // Anything that is not the literal string `gate` is report — including a typo, a null, and
        // an array. Erring toward the gate on an unreadable value would put a project into blocking
        // mode it never asked for, which is the one direction this enum must never fail in.
        return $configured === self::Gate->value ? self::Gate : self::Report;
    }
}
