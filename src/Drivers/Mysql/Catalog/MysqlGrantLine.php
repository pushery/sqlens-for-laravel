<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Catalog;

use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Catalog\SkipReason;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * One privilege grant out of `SHOW GRANTS`, split by the line's structure rather than matched by a
 * pattern.
 *
 * ## Why not a regex
 *
 * MySQL writes identifiers in backticks, with a doubled backtick for a literal one, and a backticked
 * identifier may carry any character — a space, a comma, a parenthesis, the words ` ON ` and ` TO `.
 * The pattern this replaced read `GRANT (.+) ON (\S+) TO (\S+)(.*)`, and `\S+` has no room for a
 * space. Measured on 8.4.10: a grant on a database with a space in its name matched nothing, which
 * the reading then took for a role membership and dropped; a user with a space in its name matched,
 * with the grantee cut at the space. A pattern with room for spaces would still anchor on the wrong
 * ` ON ` the moment a name contained one.
 *
 * So each line is walked once, with backticked spans and parenthesized column lists opaque, and the
 * keywords are recognized only at the top level. There is no backtracking in it, which also retires
 * the one outcome a pattern had and a walk does not: the engine giving up on a long line.
 *
 * ## What is kept, and what is skipped
 *
 * A privilege grant — `GRANT … ON … TO …` — is kept. A role membership (`GRANT `r`@`%` TO …`, no ON)
 * is skipped silently, because it belongs to the role reading and nothing about a grant is lost. So
 * is a line that is not a GRANT at all. A GRANT that carries an ON and still does not parse is the one
 * outcome that is never skipped silently: it may grant a privilege, so it is named in the skips.
 */
final readonly class MysqlGrantLine
{
    /**
     * @param  list<string>  $privileges  each entry as written, a column list included — `SELECT (`a`, `b`)`
     * @param  string  $object  as written, backticks included — `` `app`.* ``
     * @param  string  $grantee  as written, backticks included — `` `u`@`%` ``
     */
    private function __construct(
        public array $privileges,
        public string $object,
        public string $grantee,
        public bool $grantable,
    ) {}

    /**
     * The privilege grants among `SHOW GRANTS` lines, in order.
     *
     * @param  list<string>  $lines
     * @param  list<CatalogSkip>  $skips  a line that may grant a privilege and does not parse is added here
     * @return list<self>
     */
    public static function read(array $lines, array &$skips): array
    {
        $grants = [];

        foreach ($lines as $line) {
            if (strncasecmp($line, 'GRANT ', 6) !== 0) {
                continue;
            }

            $on = self::topLevel($line, ' ON ', 6);

            if ($on === null) {
                continue;
            }

            $to = self::topLevel($line, ' TO ', $on + 4);

            if ($to === null) {
                $skips[] = CatalogSkip::for(
                    SchemaObjectType::Grant,
                    'show grants',
                    SkipReason::NotUnderstood,
                    'a GRANT line carried an ON clause and no grantee this reading could find, so whatever it grants was not read',
                );

                continue;
            }

            $rest = substr($line, $to + 4);
            $end = self::topLevel($rest, ' ', 0) ?? strlen($rest);

            $grants[] = new self(
                self::split(substr($line, 6, $on - 6)),
                substr($line, $on + 4, $to - $on - 4),
                substr($rest, 0, $end),
                stripos(substr($rest, $end), 'with grant option') !== false,
            );
        }

        return $grants;
    }

    /**
     * The first position at or after $from where $needle stands outside backticks and parentheses.
     *
     * Case-insensitive, because the keywords are. A doubled backtick inside a quoted span is a
     * literal backtick and does not end the span.
     */
    private static function topLevel(string $subject, string $needle, int $from): ?int
    {
        $quoted = false;
        $depth = 0;
        $width = strlen($needle);

        for ($i = $from, $length = strlen($subject); $i < $length; $i++) {
            $character = $subject[$i];

            if ($character === '`') {
                if ($quoted && ($subject[$i + 1] ?? '') === '`') {
                    $i++;
                } else {
                    $quoted = ! $quoted;
                }

                continue;
            }

            if ($quoted) {
                continue;
            }

            if ($character === '(') {
                $depth++;
            } elseif ($character === ')') {
                $depth--;
            } elseif ($depth === 0 && strncasecmp(substr($subject, $i, $width), $needle, $width) === 0) {
                return $i;
            }
        }

        return null;
    }

    /**
     * The privilege list split at its top-level commas, so a column list stays one entry.
     *
     * @return list<string>
     */
    private static function split(string $privileges): array
    {
        $entries = [];
        $start = 0;

        while (($comma = self::topLevel($privileges, ',', $start)) !== null) {
            $entries[] = trim(substr($privileges, $start, $comma - $start));
            $start = $comma + 1;
        }

        $entries[] = trim(substr($privileges, $start));

        return $entries;
    }
}
