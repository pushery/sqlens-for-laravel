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
     * Every cast name Laravel treats as a built-in, as of the version this build was measured
     * against.
     *
     * ## Why this list has to exist at all
     *
     * `Model::$primitiveCastTypes` is `protected static`, so a package cannot read it at runtime —
     * the same wall as `isEncryptedCastable()`, solved the same way: a constant here, and a drift
     * test that holds it against the framework and goes red when they part company.
     *
     * ## Why the check cannot be skipped
     *
     * `class_exists('datetime')` is TRUE. PHP resolves class names without regard to case and
     * `DateTime` exists, so a `datetime:Y-m-d` column would read as an opaque custom cast and the
     * rule would fall silent over a column that really is in the clear. Measured over all of the
     * entries below, that collision is the only one — and it is the built-in most likely to carry
     * an argument in a real application.
     *
     * The colon-bearing entries (`encrypted:json`, `json:unicode`) can never match a head, which is
     * what is compared against this list. They are kept so the drift test can compare the whole
     * list for equality rather than a filtered version of it.
     *
     * @var list<string>
     */
    public const array PRIMITIVES = [
        'array',
        'bool',
        'boolean',
        'collection',
        'custom_datetime',
        'date',
        'datetime',
        'decimal',
        'double',
        'encrypted',
        'encrypted:array',
        'encrypted:collection',
        'encrypted:json',
        'encrypted:object',
        'float',
        'hashed',
        'immutable_date',
        'immutable_datetime',
        'immutable_custom_datetime',
        'int',
        'integer',
        'json',
        'json:unicode',
        'object',
        'real',
        'string',
        'timestamp',
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
        // A colon does not mean a built-in. Laravel documents a custom cast with arguments in
        // exactly that shape — `Hash::class.':sha256'` — so a class cast and a parameterized
        // built-in are indistinguishable by the presence of a colon. Returning false on sight of
        // one would send every argumented class cast down the unprotected path: the same cast class
        // would read `undetermined` without an argument and "stored in the clear" with one. On this
        // rule that is not a missed finding, it is a false statement about a column's protection.
        //
        // So the arguments come off first, which is what the framework does in `parseCasterClass()`
        // before it decides anything.
        $head = str_contains($cast, ':') ? explode(':', $cast, 2)[0] : $cast;

        // Laravel's own order, and this line is the load-bearing one: `class_exists('datetime')` is
        // TRUE. Without the built-in check, `datetime:Y-m-d` becomes an opaque custom cast and the
        // rule goes quiet about a column in the clear — a false positive traded for a false
        // negative, which is the worse half of the exchange because nobody notices it.
        //
        // Compared case-sensitively, as the framework compares it. `DateTime:Y-m-d` is a class cast
        // to Laravel, and answering `undetermined` for it is both agreement with the framework and
        // the cautious direction.
        if (in_array($head, self::PRIMITIVES, true)) {
            return false;
        }

        return class_exists($head) || interface_exists($head);
    }
}
