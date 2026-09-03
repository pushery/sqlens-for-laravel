<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Pushery\SQLens\Catalog\Canonical\IdentifierFolding;

/**
 * What MySQL's `secure_file_priv` actually says — a value whose naive reading is INVERTED.
 *
 * The setting decides how far the `FILE` privilege reaches: whether an account holding it can read
 * and write anywhere the server process can, only inside one directory, or nowhere at all. Three
 * server states, and MySQL spells them in a way that punishes the obvious reading:
 *
 * | Raw value | Means | What a naive reading makes of it |
 * |---|---|---|
 * | `'NULL'` — the four-character STRING | file I/O disabled; the SAFEST state | "some value, so it is set, so probably fine" |
 * | `''` | unrestricted; the MOST DANGEROUS state | "empty, so nothing is set, so it does not matter" |
 * | a path | confined to that directory | correct |
 *
 * Measured on MySQL 8.4.10, through both read paths — `performance_schema.global_variables` and
 * `SHOW GLOBAL VARIABLES` both report the disabled state as the literal string `NULL`, never as SQL
 * NULL. So an `is_null()`, an `empty()` or a `?: 'unset'` at this point does not merely lose
 * precision: it swaps the two ends of the scale, and reports the safest server as the one worth
 * ignoring while the most dangerous one looks unconfigured.
 *
 * ## Why there is a fourth case rather than a null
 *
 * {@see PasswordHashType} states the reason for its own `Withheld` case, and it applies here with
 * more force: a null invites `?? self::Disabled`, and "we could not look" would silently become "it
 * is switched off" — turning an unmeasured server into a clean bill of health. Here the substitution
 * would be worse still, because the two states a caller might collapse are opposites.
 *
 * The shape follows {@see IdentifierFolding}: a string-backed enum
 * with a static factory named after the variable it reads, and a `default` arm whose choice is
 * argued rather than assumed.
 */
enum SecureFilePrivState: string
{
    /**
     * `LOAD_FILE()` and `SELECT … INTO OUTFILE` are switched off entirely.
     *
     * MySQL writes this as the four-character string `NULL`. The value that looks like an accident
     * is the one a hardened server has.
     */
    case Disabled = 'disabled';

    /**
     * File I/O reaches anywhere the server's operating-system user can reach.
     *
     * The empty string, and the state this whole enum exists to keep visible: it is what an
     * unconfigured `my.cnf` leaves behind on some builds, and it reads to the eye like "nothing set".
     */
    case Unrestricted = 'unrestricted';

    /** Confined to one directory. A deliberate limit, and the ordinary answer on a managed server. */
    case Restricted = 'restricted';

    /**
     * The setting was not read — a refused variable, a server that does not carry it, a reading that
     * failed.
     *
     * A named case rather than a null, for the reason in the class docblock. Nothing may treat this
     * as any of the three above; a rule meeting it reports that it could not check.
     */
    case Unknown = 'unknown';

    /**
     * Classify the value the SERVER reports for `secure_file_priv`.
     *
     * `null` here means the reading did not produce the variable at all, which is a different fact
     * from every value it could have produced — hence {@see self::Unknown} rather than a guess.
     *
     * The comparison against `NULL` is case-insensitive and trimmed: the value travels through a
     * config file, a client and two catalog surfaces, and none of them promises a canonical casing.
     * Matching only the exact upper-case spelling would classify a server written as `secure-file-priv
     * = null` as unrestricted — the single most dangerous misreading this type exists to prevent.
     */
    public static function forServerValue(?string $value): self
    {
        if ($value === null) {
            return self::Unknown;
        }

        $trimmed = trim($value);

        if ($trimmed === '') {
            return self::Unrestricted;
        }

        if (strcasecmp($trimmed, 'NULL') === 0) {
            return self::Disabled;
        }

        // Anything else is a path. Deliberately the default rather than a pattern match on what a
        // path looks like: a filesystem accepts names this package has no business predicting, and
        // between two wrong answers the one that says "confined" for an odd-looking directory is
        // better than the one that says "unrestricted" and sends somebody to fix a server that is
        // already limited.
        return self::Restricted;
    }

    /** Whether this state leaves the `FILE` privilege reaching the whole host. */
    public function isUnrestricted(): bool
    {
        return $this === self::Unrestricted;
    }

    /** How to say this state in a finding, in the server's own terms. */
    public function describe(): string
    {
        return match ($this) {
            self::Disabled => 'switched off entirely (the value NULL)',
            self::Unrestricted => 'unrestricted (the empty value)',
            self::Restricted => 'confined to one directory',
            self::Unknown => 'not readable on this server',
        };
    }
}
