<?php

declare(strict_types=1);

namespace Pushery\SQLens;

use Composer\InstalledVersions;
use Throwable;

/**
 * Which version of this package is running — asked in one place, answered one way.
 *
 * ## Why this exists rather than one line repeated
 *
 * It was four spellings repeated, and two of them were wrong. `sqlens:audit` and `sqlens:security`
 * read a config key named `sqlens.version` that does not exist — not in the schema, not in the
 * shipped config file — so both fell back to the literal `0.0.0` and PRINTED it, in the run header
 * and in the JSON envelope, which is public API. `sqlens:lint` read the real version from Composer
 * the whole time, so two commands in one package disagreed about the version that produced the
 * report, and the one that was wrong looked like a release.
 *
 * Nothing was red, and nothing could be: a fallback that always runs is indistinguishable from a
 * fallback that never does, and both write a plausible string. What surfaced it was asking whether
 * every config path the code READS is one the validator accepts — the direction the schema had never
 * been checked in, now held by `tests/Unit/Config/ConfigKeysAreReadableTest.php`.
 *
 * ## Why Composer and not config
 *
 * A published config file is not rewritten when the package updates. A version stored there would
 * pin whatever a project installed first and keep announcing it for as long as the file survives —
 * a wrong answer that ages, which is worse than no answer.
 */
final readonly class PackageVersion
{
    public const string PACKAGE = 'pushery/sqlens-for-laravel';

    /**
     * The stand-in when Composer cannot say, as a SENTENCE rather than a number.
     *
     * `0.0.0` reads as a version and sends a reader hunting for a release that does not exist. This
     * says what actually happened, which is that the run does not know.
     */
    public const string UNKNOWN = 'unknown (package version not reported by Composer)';

    /**
     * The installed version, or {@see self::UNKNOWN}.
     *
     * The package name is a parameter with a default rather than a hard-coded constant, and that is
     * a testability seam admitted out loud: the failure path matters more than the happy one here —
     * it is the path that used to print `0.0.0` — and inside this suite the package is always
     * installed, so a hard-coded name would make the branch that handles absence unreachable. A
     * branch no test can enter is one nobody has checked.
     */
    public static function current(string $package = self::PACKAGE): string
    {
        try {
            $version = InstalledVersions::getPrettyVersion($package);
        } catch (Throwable) {
            // Not installed as a Composer package — a checkout running from source, or a name that
            // does not exist. Either way the run does not know, and says so.
            return self::UNKNOWN;
        }

        return $version !== null && $version !== '' ? $version : self::UNKNOWN;
    }

    /**
     * The same fact, shortened for a request header.
     *
     * A User-Agent is read in an access log, where a parenthetical sentence is noise. `dev` is the
     * conventional short form and says the same thing in the space available.
     */
    public static function forUserAgent(string $package = self::PACKAGE): string
    {
        $version = self::current($package);

        return $version === self::UNKNOWN ? 'dev' : $version;
    }
}
