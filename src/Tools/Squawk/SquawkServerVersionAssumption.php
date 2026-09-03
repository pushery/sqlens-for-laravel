<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Squawk;

use Pushery\SQLens\Engine\ResolvedServerVersion;
use Pushery\SQLens\Rules\ServerVersion;

/**
 * Which PostgreSQL version the tool is told to judge against — the SAME one the core rules used.
 *
 * The pin is not re-derived here. The run already resolved a version, from a configured
 * `assume_server_version` or from the server itself, and this reads that decision rather than
 * making a second one. Two derivations of the same fact is how the two halves of a run come to
 * disagree without anything saying so.
 *
 * And it is measurably load-bearing, not a formality: the same `ADD COLUMN ... DEFAULT` is a
 * finding at target version 10 and silence at 11, because the operation became metadata-only in
 * PostgreSQL 11. A report whose core rules reasoned about PostgreSQL 18 and whose amplifier
 * reasoned about the tool's own default would be one document describing two servers.
 */
final readonly class SquawkServerVersionAssumption
{
    /**
     * The shape the tool accepts, and it is strict on OUR side for a measured reason.
     *
     * Handed something non-numeric, the tool exits 2 with "Invalid number in version" — measured.
     * That would arrive as a failed run, which is true and useless: the cause is a version string
     * this package built, not a tool that misbehaved. Refusing it here names the real problem.
     */
    private const string ACCEPTED_SHAPE = '/^\d+\.\d+$/';

    /**
     * The assumption for this run, or the named reason there is none.
     *
     * Never a fallback to the tool's own default. That is the whole point of the case: a default
     * is an answer to a different question, and adopting it silently produces a report that looks
     * complete.
     */
    public static function forRun(ResolvedServerVersion $resolved): string|SquawkFailureReason
    {
        $version = $resolved->version;

        if (! $version instanceof ServerVersion) {
            return SquawkFailureReason::PgVersionUnknown;
        }

        // Major and minor only. The tool takes `X.Y`; a patch level would be rejected outright,
        // and it decides nothing here anyway — no rule in it turns on a patch release.
        $assumption = $version->major.'.'.$version->minor;

        return preg_match(self::ACCEPTED_SHAPE, $assumption) === 1
            ? $assumption
            : SquawkFailureReason::PgVersionUnknown;
    }
}
