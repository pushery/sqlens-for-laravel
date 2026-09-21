<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

/**
 * The MySQL accounts that belong to the SERVER, recognized by name alone.
 *
 * A migration statement carries names, never privileges. So a rule reading a migration can answer
 * *"is this account one the server created for itself"* and cannot answer *"is this account
 * privileged"* — the second needs the catalog, and pretending otherwise is the failure this class
 * exists to avoid.
 *
 * ## The prefix, not a list of three, and the reason is already in the tree
 *
 * `MysqlSecurityReader` marks an engine account from `mysql.` rather than from names, with its own
 * note: *"8.4 added `mysql.infoschema` to what 5.7 had, and a hard-coded list would have gone stale
 * exactly once, silently."* This class uses the same prefix rather than a second list, because two
 * lists of the server's own accounts is exactly the drift that note is about.
 *
 * ## `root` is separate, and it is a CONVENTION rather than a reserved name
 *
 * MySQL does not reserve `root`; an installation may rename it, and hardening guides tell people
 * to. So it sits beside the prefix rather than inside it, and the limitation is stated where the
 * rule states its limitations rather than hidden here. Measured on 8.4.10: `root@localhost` and
 * `mysql.session@localhost` both carry `Super_priv = Y`, `mysql.sys` and `mysql.infoschema` do not
 * — and all three `mysql.` accounts ship `account_locked = Y`.
 */
final class MysqlSystemAccounts
{
    /** What MySQL names its own accounts with — the same prefix the catalog reader marks them by. */
    public const string ENGINE_PREFIX = 'mysql.';

    /**
     * The conventional superuser.
     *
     * Not a reserved name and not the only privileged account an installation has. It is here
     * because it is the one an example, a tutorial and a hurried migration all reach for.
     */
    public const string CONVENTIONAL_SUPERUSER = 'root';

    /** Whether this account name is one the server owns, or the conventional superuser. */
    public static function isAdministrative(string $user): bool
    {
        $name = strtolower(trim($user, "`'\" "));

        return $name === self::CONVENTIONAL_SUPERUSER || str_starts_with($name, self::ENGINE_PREFIX);
    }

    /**
     * What this account is, for a message that should say which kind it found.
     *
     * Two sentences rather than one, because the two cases call for different reading: an engine
     * account is the server's own and a project should never be impersonating it, while `root` is a
     * name a project may legitimately have renamed or replaced.
     */
    public static function describe(string $user): string
    {
        $name = strtolower(trim($user, "`'\" "));

        return str_starts_with($name, self::ENGINE_PREFIX)
            ? 'an account the server created for itself'
            : 'the conventional superuser';
    }
}
