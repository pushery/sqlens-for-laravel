<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Convention;

/**
 * Whether an identifier survives the server's length limit, measured the way that server measures.
 *
 * ## Two engines, two limits, and two UNITS — measured rather than read
 *
 * Against PostgreSQL 18.4 and MySQL 8.4.10:
 *
 * ```
 * PG   64 ASCII chars       NOTICE: identifier "aaa…" will be truncated to "aaa…"   → created, RENAMED
 * PG   32 two-byte chars    NOTICE: … truncated to 31 characters                    → created, RENAMED
 * MY   65 ASCII chars       ERROR 1059: Identifier name 'bbb…' is too long          → refused
 * MY   32 two-byte chars    created                                                 → fine
 * ```
 *
 * The multibyte row is the one that decides the implementation. PostgreSQL's limit is **63 bytes**,
 * so thirty-two two-byte characters are already over it — and a rule counting characters would pass
 * exactly that identifier while the server quietly renames the object. MySQL's limit is **64
 * characters**, so the same name is fine there. One rule, two units, and getting the unit wrong is
 * silent in the direction that matters.
 *
 * ## Why PostgreSQL's case is the worse one
 *
 * MySQL refuses the statement: the deploy stops, at the moment somebody is watching, with the
 * offending name in the message. PostgreSQL creates the object under a DIFFERENT NAME and says so in
 * a `NOTICE` — which no migration runner surfaces. Every later reference by the name that was
 * written then fails, long after the deploy that caused it.
 *
 * ## Both drivers report it at the SAME level, and that is a decision
 *
 * The first plan put PostgreSQL at level 4 and MySQL at level 8, reading the loud refusal as the
 * milder problem. That was wrong twice over. A statement the server refuses is not a matter of
 * convention — it is a deploy that stops — and level 8 is where preference lives. And the category
 * follows the base class, so a MySQL rule at level 8 would have had to claim `safety` inside the
 * convention band, which contradicts what the bands mean.
 *
 * So both sit at level 4, and the asymmetry lives where it actually is: in the UNIT each engine
 * measures with, and in what each one does to the statement. Neither of those is a strictness
 * appetite.
 */
final readonly class IdentifierLength
{
    /** PostgreSQL's `NAMEDATALEN - 1`, and it counts BYTES. */
    public const int POSTGRES_BYTES = 63;

    /** MySQL's limit for most object names, and it counts CHARACTERS. */
    public const int MYSQL_CHARACTERS = 64;

    /**
     * Whether this identifier is over the limit, measured in the given unit.
     *
     * `mb_strlen` with an explicit encoding rather than the ambient one: the default depends on
     * `mbstring.internal_encoding`, so the same name would measure differently on two machines —
     * and a length rule whose answer moves with a php.ini is worse than no length rule.
     */
    public static function exceeds(string $identifier, int $limit, bool $inBytes): bool
    {
        $bare = self::bareName($identifier);

        return ($inBytes ? strlen($bare) : mb_strlen($bare, 'UTF-8')) > $limit;
    }

    /**
     * What the server would leave, so the finding can show it rather than describe it.
     *
     * PostgreSQL truncates to whole CHARACTERS within the byte budget — a cut that split a
     * multibyte sequence would produce invalid UTF-8, which it does not do. `mb_strcut` is the
     * function with that behavior; `substr` is not.
     */
    public static function truncated(string $identifier, int $limitBytes): string
    {
        return mb_strcut(self::bareName($identifier), 0, $limitBytes, 'UTF-8');
    }

    /** The last segment of a possibly-qualified name. */
    public static function bareName(string $identifier): string
    {
        $parts = explode('.', $identifier);

        return trim(end($parts), '"`[] ');
    }
}
