<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Analyse;

/**
 * How the security run gets at the injection findings, which live in a PHPStan extension.
 *
 * The injection rules are the one family whose subject is PHP source rather than a database, so they
 * run inside PHPStan rather than inside this package's own engine. That is deliberate — a second
 * static analyzer would be a second opinion about the same code — and it leaves the security run one
 * question: how does it learn what PHPStan found?
 *
 * ## Why `off` is a mode rather than the absence of one
 *
 * A project that has not wired the analyse half is not a project whose code is free of raw SQL. It is
 * a project nobody looked at. `off` says that out loud, and the run reports it: the half did not run,
 * with the reason. Leaving the setting absent and staying silent would make an unexamined codebase
 * indistinguishable from a clean one, which is the failure this whole package is built against.
 */
enum AnalyseMode: string
{
    /**
     * The shipped state. The half does not run, and the run SAYS the half did not run.
     *
     * Not "no findings" — no reading. The difference is the entire point of the three-valued model,
     * and it is why this is the default rather than an omission: a default that stayed quiet would
     * be a promise nobody made.
     */
    case Off = 'off';

    /**
     * Read a result PHPStan has already written, from a configured path.
     *
     * The ordinary shape in CI, where PHPStan runs as its own step and both steps see the same
     * workspace. It is also the honest one: this package reports what another tool found and says
     * whose finding it is, rather than orchestrating an analyzer it does not own.
     */
    case Read = 'read';

    /** The mode this setting accepts, for a message that has to list them. */
    public static function names(): string
    {
        return implode(', ', array_map(static fn (self $mode): string => $mode->value, self::cases()));
    }
}
