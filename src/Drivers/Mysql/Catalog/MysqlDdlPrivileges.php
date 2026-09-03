<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Catalog;

use JsonException;
use Pushery\SQLens\Exceptions\InvalidRuleEvidence;

/**
 * The MySQL privileges that let an account decide what EXISTS, rather than what a row contains.
 *
 * The canonical privilege vocabulary is PostgreSQL's, and almost none of these have a PostgreSQL
 * equivalent — `ALTER`, `DROP`, `INDEX`, `CREATE ROUTINE` and `EVENT` all arrive as the unmapped
 * case, carrying their own engine name. So a structural check written against the canonical cases
 * asks, on MySQL, only whether the account holds `CREATE`: `TRUNCATE` and `ALTER SYSTEM` do not
 * exist on that engine at all.
 *
 * The consequence is the one this package exists to refuse. An account that may rebuild every table,
 * drop every table, and install code as a stored routine reads as holding nothing structural — and a
 * rule asking the question comes back silent, looking exactly like a rule with nothing to report.
 *
 * ## Why a driver class rather than a list in the rule
 *
 * `CorePurityArchTest` keeps every core namespace free of a driver reference and of an engine's
 * vocabulary, with the exemptions pinned to four composition roots. That is the right rule and this
 * is the shape it asks for: the READER stamps the fact, and the rule reads a boolean.
 *
 * ## What is deliberately NOT here
 *
 * The artifact records those too, with reasons, because the omissions are the part somebody will
 * otherwise re-add. `REFERENCES` is the sharpest: MySQL requires it on the PARENT table to create a
 * foreign key, but the statement also needs `ALTER` or `CREATE` on the child — so an account holding
 * only `REFERENCES` can change no schema at all, and reporting it would be a finding against the
 * claim the rule makes.
 */
final readonly class MysqlDdlPrivileges
{
    /** The artifact format this reader implements; an unknown version is an error, never a default. */
    public const int SCHEMA_VERSION = 1;

    /** The one place the path lives, so a relocation is a single edit. */
    public const string BUNDLED_FILE = 'resources/data/mysql-ddl-privileges.json';

    /** @param  list<string>  $privileges  upper-cased MySQL privilege names */
    private function __construct(
        public string $referenceServer,
        public array $privileges,
    ) {}

    /** The bundled artifact, parsed once per process — the grants reading builds on the fast path. */
    public static function bundled(): self
    {
        static $bundled = null;

        if (! $bundled instanceof self) {
            $bundled = self::fromFile(dirname(__DIR__, 4).'/'.self::BUNDLED_FILE);
        }

        return $bundled;
    }

    public static function fromFile(string $path): self
    {
        $raw = @file_get_contents($path);

        if ($raw === false) {
            throw InvalidRuleEvidence::unreadable($path);
        }

        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw InvalidRuleEvidence::unparsable($path, $exception->getMessage());
        }

        return self::fromArray($decoded, $path);
    }

    /** @param  array<string, mixed>  $data */
    public static function fromArray(array $data, string $origin): self
    {
        if (($data['schema_version'] ?? null) !== self::SCHEMA_VERSION) {
            throw InvalidRuleEvidence::unsupportedSchemaVersion($origin, $data['schema_version'] ?? null, self::SCHEMA_VERSION);
        }

        $known = ['schema_version', 'reference_server', 'about', 'entries', 'deliberately_absent'];

        foreach (array_keys($data) as $key) {
            if (! in_array($key, $known, true)) {
                throw InvalidRuleEvidence::malformed($origin, (string) $key, 'not a known field of the artifact');
            }
        }

        $entries = $data['entries'] ?? null;

        if (! is_array($entries) || ! array_is_list($entries)) {
            throw InvalidRuleEvidence::malformed($origin, 'entries', 'a list');
        }

        $names = [];

        foreach ($entries as $entry) {
            if (! is_array($entry)) {
                throw InvalidRuleEvidence::malformed($origin, 'entries', 'each entry an object');
            }

            $privilege = $entry['privilege'] ?? null;

            // Checked rather than cast. A name that is not a string is a broken artifact, and a cast
            // would turn it into one the comparison then runs against — matching nothing, forever,
            // and looking exactly like a server where nobody holds a structural privilege.
            if (! is_string($privilege) || preg_match('/^[A-Z]+( [A-Z]+)*$/', $privilege) !== 1) {
                throw InvalidRuleEvidence::malformed($origin, 'privilege', 'an upper-case MySQL privilege name, single spaces only');
            }

            if (in_array($privilege, $names, true)) {
                throw InvalidRuleEvidence::malformed($origin, 'entries', "one entry per privilege — \"{$privilege}\" appears more than once");
            }

            $names[] = $privilege;
        }

        // An empty artifact would make every MySQL grant read as non-structural — precisely the
        // defect this file was written to end, arriving through an omission instead of an oversight.
        if ($names === []) {
            throw InvalidRuleEvidence::malformed($origin, 'entries', 'at least one entry — an empty list classifies nothing as structural');
        }

        $server = $data['reference_server'] ?? null;

        if (! is_string($server) || $server === '') {
            throw InvalidRuleEvidence::malformed($origin, 'reference_server', 'a non-empty string');
        }

        return new self($server, $names);
    }
}
