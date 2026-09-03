<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use JsonException;

/**
 * The MySQL privileges that make an account an administrator of the SERVER.
 *
 * A shipped data artifact rather than a list in a rule, and the reason is the one the engine itself
 * demonstrates: `SUPER` was deprecated in 8.0 and its powers split across a family of dynamic
 * privileges, so a check that looks only for `SUPER` comes back empty on a correctly configured 8.4
 * whose account is administrator in every way that matters.
 *
 * A list in code is a list nobody reconciles against the server. This one is reconciled by a test
 * that asks a REAL MySQL to accept every name — and that reconciliation earned itself on its first
 * run: the list was written carrying `SET_USER_ID`, which 8.4 refuses outright. It was split into
 * `SET_ANY_DEFINER` and `ALLOW_NONEXISTENT_DEFINER`, and a rule reading the old name would have
 * matched nothing on the engine this package targets while looking exactly like a rule with nothing
 * to report.
 */
final class MysqlAdminPrivileges
{
    /** @var list<string>|null */
    private static ?array $judged = null;

    /**
     * The privilege names this rule judges, upper-cased the way MySQL reports them.
     *
     * An entry marked `judged: false` is part of the VOCABULARY but owned by another rule —
     * `GRANT OPTION` belongs to SEC.PRIV.GRANT_OPTION, and two rules about one fact is the double
     * report this catalog refuses.
     *
     * @return list<string>
     */
    public static function judged(): array
    {
        if (self::$judged !== null) {
            return self::$judged;
        }

        $path = dirname(__DIR__, 3).'/resources/data/mysql-admin-privileges.json';
        $raw = @file_get_contents($path);

        if ($raw === false) {
            // An artifact this rule cannot read is not an empty list — an empty list would make the
            // rule silently correct about every server. It is a broken installation, and the loudest
            // honest answer available here is no entries plus a shipped guard that proves the file is
            // present. The guard is the mechanism; this is only the fallback that cannot lie.
            return self::$judged = [];
        }

        try {
            $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return self::$judged = [];
        }

        $entries = is_array($decoded) && is_array($decoded['entries'] ?? null) ? $decoded['entries'] : [];
        $names = [];

        foreach ($entries as $entry) {
            if (! is_array($entry)) {
                continue;
            }
            if (($entry['judged'] ?? true) !== true) {
                continue;
            }
            // Checked rather than cast: a name that is not a string is a broken artifact, and a cast
            // would turn it into one the rule then judges against. Skipping it keeps the list to what
            // the file actually says, and the shipped guard is what makes the omission visible.
            if (! is_string($entry['privilege'] ?? null)) {
                continue;
            }

            $names[] = strtoupper($entry['privilege']);
        }

        sort($names);

        return self::$judged = $names;
    }

    /** Whether this MySQL privilege name is one of the administrative ones. */
    public static function isAdministrative(string $privilege): bool
    {
        return in_array(strtoupper(trim($privilege)), self::judged(), true);
    }
}
