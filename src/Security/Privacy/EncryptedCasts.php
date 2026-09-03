<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Privacy;

use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * The Eloquent casts that mean "this column is encrypted at rest".
 *
 * ## Why the list is carried here and not asked of Laravel at runtime
 *
 * `HasAttributes::isEncryptedCastable()` is `protected`, so a package cannot call it. The spike
 * behind this class read the family out of the framework's SOURCE with a regex, which is the right
 * shape for a test and the wrong shape for a shipped run: a moved file or a reworded method turns
 * the regex into an empty list, and an empty list here means every encrypted column reads as
 * unprotected — a false-positive storm on the loudest rule in the suite, arriving silently.
 *
 * So the operational list is a constant, and the DRIFT is a test: `EncryptedCastDiscoveryTest`
 * compares this constant against what the framework actually implements and goes red when they
 * part company. The failure then lands at build time, on the person who upgraded Laravel, instead
 * of at audit time on somebody's schema.
 *
 * ## Five forms, not three
 *
 * The ticket that asked for this named three. Measured against Laravel 13, there are five — and
 * reading four of five is worse than reading none, because it under-reports on a real application
 * while looking like it works.
 */
final readonly class EncryptedCasts
{
    /**
     * Every cast Laravel treats as encrypted, as of the version this build was measured against.
     *
     * @var list<string>
     */
    public const array FAMILY = [
        'encrypted',
        'encrypted:array',
        'encrypted:collection',
        'encrypted:json',
        'encrypted:object',
    ];

    /**
     * Whether a cast declaration means the value is encrypted at rest.
     *
     * Compared whole, never by prefix. `encrypted` is a prefix of `encryptedX`, and a project is
     * free to name a custom cast that way — reading it as the framework's own would be this package
     * asserting protection it never verified, which is the one direction that must never be guessed.
     */
    public static function protects(string $cast): bool
    {
        return in_array($cast, self::FAMILY, true);
    }

    /**
     * Whether a cast declaration is a class rather than one of Laravel's own names.
     *
     * A custom castable may encrypt and may not, and the only way to find out is to run somebody
     * else's code. That is refused, so the answer is `undetermined` — see
     * {@see UndeterminedReason::CustomCastOpaque}.
     */
    public static function isCustomCastable(string $cast): bool
    {
        // A parameterized built-in carries a colon (`decimal:2`, `encrypted:json`); a class does
        // not, and the ones that matter here resolve. Checked in that order so `encrypted:json`
        // can never be mistaken for a class name.
        if (str_contains($cast, ':')) {
            return false;
        }

        return class_exists($cast) || interface_exists($cast);
    }
}
