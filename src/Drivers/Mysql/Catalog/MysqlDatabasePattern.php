<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Catalog;

/**
 * The database name of a database-level grant, read the way MySQL reads it.
 *
 * In `GRANT … ON db.*` the name is a pattern: `%` matches any run of characters and `_` exactly one,
 * unless the server runs with `partial_revokes`, which makes both literal. A backslash makes the next
 * character literal, which is how a grant spells the underscores of a prefix.
 */
final readonly class MysqlDatabasePattern
{
    /**
     * Whether a database-level grant names $name. Compared case-sensitively, which can only make a
     * pattern reach less than the server lets it.
     *
     * @param  bool  $wildcards  whether `_` and `%` match any character, as they do unless the server
     *                           runs with `partial_revokes`
     */
    public static function covers(string $pattern, string $name, bool $wildcards): bool
    {
        $regex = '';
        $length = strlen($pattern);

        for ($at = 0; $at < $length; $at++) {
            $character = $pattern[$at];

            if ($character === '\\' && $at + 1 < $length) {
                $at++;
                $regex .= preg_quote($pattern[$at], '/');
            } elseif ($wildcards && $character === '%') {
                $regex .= '.*';
            } elseif ($wildcards && $character === '_') {
                $regex .= '.';
            } else {
                $regex .= preg_quote($character, '/');
            }
        }

        return preg_match('/^'.$regex.'$/s', $name) === 1;
    }
}
