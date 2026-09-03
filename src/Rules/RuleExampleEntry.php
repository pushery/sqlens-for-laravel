<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Exceptions\InvalidRuleExample;

/**
 * The bad and good example for one rule: the migration that trips it, the migration
 * that does the same job safely, and one line saying what separates them.
 *
 * The examples are what a user and an agent read to understand a finding — the fixture
 * proves the rule, the example explains it. They are OUR wording: the facts (what an
 * operation does, which lock it takes) are free, but the phrasing and the snippets are
 * written here, never lifted from another tool's or the database's documentation. A
 * paraphrase close enough to be a copy is a copy, and the register would then ship
 * someone else's text under this package's license.
 *
 * Both snippets are normally Laravel migration bodies, kept short and runnable; a completeness
 * test parses them, so an example that would not compile never ships.
 *
 * ## When the example is not PHP
 *
 * A server-baseline rule judges a server variable, and no migration can set one. Writing its
 * example as a migration body that runs `ALTER SYSTEM` would parse, ship, and teach the wrong
 * thing — server configuration does not belong in a migration, and an example is read as advice.
 * So an entry may declare its {@see self::$language}, and the completeness gate parses PHP only
 * where PHP is what was written. What a `sql` example gives up is the compile proof; the gate says
 * so rather than pretending the check still holds, which is the same three-valued honesty the rules
 * themselves are held to.
 *
 * The host-based authentication rules need the same allowance one step further out. Their subject is
 * a line in `pg_hba.conf`, which no migration and no statement can write — the file is read by the
 * server at reload, and the only text that helps a reader is the line itself. Writing it as SQL
 * would mean appending a semicolon to a config line and teaching a syntax error; writing it as PHP
 * would mean inventing a migration that cannot exist. Hence `conf`: the snippet is the line, and the
 * gate checks the field shape a `pg_hba.conf` line has rather than a grammar it does not.
 *
 * `shell` is the fourth and the same idea once more. Data checksums are decided by `initdb`, the
 * tool that CREATES the cluster — before any connection exists, by a program rather than by a
 * statement. Filed as `sql` it was held to the SQL checks and passed them only because somebody had
 * appended a semicolon, which means nothing on a command line and reads in the documentation like a
 * terminator. So the shell check is the SQL one inverted at exactly that point: a trailing semicolon
 * is REFUSED rather than required.
 *
 * ## The false-positive consideration
 *
 * A rule may also record where it is knowingly WRONG — the shapes it reports that a careful reader
 * would not. That is governance, not decoration: a rule whose author never wrote down when it cries
 * wolf has not finished thinking about it, and the first person to meet the false positive is a
 * user who then stops trusting the whole tool.
 *
 * It is optional in this reader and mandatory where a driver's completeness gate says so, which is
 * the honest staging: existing entries predate the field, and a reader that refused to load them
 * would take the whole register down over prose nobody had written yet.
 */
final readonly class RuleExampleEntry
{
    public const string LANGUAGE_PHP = 'php';

    public const string LANGUAGE_SQL = 'sql';

    /** A `pg_hba.conf` line — the only text that helps where the subject is that file. */
    public const string LANGUAGE_CONF = 'conf';

    /** A command line — for a setting decided by the tool that CREATES the cluster. */
    public const string LANGUAGE_SHELL = 'shell';

    /**
     * A `key = value` server configuration file — MySQL's `my.cnf`, PostgreSQL's `postgresql.conf`.
     *
     * Distinct from {@see self::LANGUAGE_CONF} rather than folded into it, because that one means
     * `pg_hba.conf` SPECIFICALLY: its well-formedness check reads a positional record grammar, and a
     * `key = value` line fails it. Reusing the name would have made every server-setting example
     * either unshippable or exempt from checking, and an exemption is how an example that would not
     * work reaches a reader.
     *
     * The distinction is the file's GRAMMAR, not its extension: both end in `.conf`, and only one of
     * them is positional.
     */
    public const string LANGUAGE_INI = 'ini';

    /** Every language an entry may declare, in one place so the gate and the loader cannot drift. */
    public const array LANGUAGES = [self::LANGUAGE_PHP, self::LANGUAGE_SQL, self::LANGUAGE_CONF, self::LANGUAGE_SHELL, self::LANGUAGE_INI];

    private function __construct(
        public string $bad,
        public string $good,
        public string $note,
        /** Where the rule knowingly reports something a careful reader would not, or null. */
        public ?string $falsePositives = null,
        /**
         * The language both snippets are written in — `php` unless stated otherwise.
         *
         * Defaulted rather than required: every entry that predates the field is a migration body,
         * and making it mandatory would have meant editing all of them to restate what was already
         * true. A new entry says `sql` only when it genuinely is.
         */
        public string $language = self::LANGUAGE_PHP,
    ) {}

    /** @param  array<string, mixed>  $data */
    public static function fromArray(array $data, string $origin, string $ruleId): self
    {
        $where = "entries.{$ruleId}";

        return new self(
            bad: self::string($data, 'bad', $origin, $where),
            good: self::string($data, 'good', $origin, $where),
            note: self::string($data, 'note', $origin, $where),
            falsePositives: self::optionalString($data, 'false_positives', $origin, $where),
            language: self::language($data, $origin, $where),
        );
    }

    /**
     * The declared language, validated against the two this package knows.
     *
     * An unknown value is an error rather than a silent fallback to PHP: a typo'd `sqll` would
     * otherwise send a SQL snippet through the PHP parser, fail, and read as a broken example
     * instead of a broken register.
     *
     * @param  array<string, mixed>  $data
     */
    private static function language(array $data, string $origin, string $where): string
    {
        if (! array_key_exists('language', $data)) {
            return self::LANGUAGE_PHP;
        }

        $value = self::string($data, 'language', $origin, $where);

        if (! in_array($value, self::LANGUAGES, true)) {
            throw InvalidRuleExample::malformed($origin, $where.'.language', 'one of "'.implode('", "', self::LANGUAGES).'"');
        }

        return $value;
    }

    /**
     * An optional field: absent is fine, present-but-empty is not.
     *
     * The distinction matters. An absent field is an entry written before the field existed; an
     * empty one is somebody satisfying a checklist without saying anything, which is worse than
     * leaving it out because it reads as answered.
     *
     * @param  array<string, mixed>  $data
     */
    private static function optionalString(array $data, string $key, string $origin, string $where): ?string
    {
        if (! array_key_exists($key, $data)) {
            return null;
        }

        return self::string($data, $key, $origin, $where);
    }

    /** @param  array<string, mixed>  $data */
    private static function string(array $data, string $key, string $origin, string $where): string
    {
        $value = $data[$key] ?? null;

        if (! is_string($value) || trim($value) === '') {
            throw InvalidRuleExample::malformed($origin, $where.'.'.$key, 'a non-empty string');
        }

        return $value;
    }
}
