<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Catalog;

use JsonException;
use Pushery\SQLens\Exceptions\InvalidRuleEvidence;

/**
 * MySQL's static privileges and the grant-table column each one lives in.
 *
 * MySQL stores a static privilege as one `Y`/`N` COLUMN per privilege — `mysql.user` for global
 * scope, `mysql.db` for database scope — and the column name is not the privilege name.
 * `Show_db_priv` is `SHOW DATABASES`; `Repl_slave_priv` is `REPLICATION SLAVE`. Something has to
 * carry that mapping, and carrying it inside the query is how it rotted the first time: the reader
 * unpivoted ten of `mysql.db`'s eighteen privilege columns and none of `mysql.user`'s thirty, so an
 * account holding `ALL PRIVILEGES ON *.*` arrived at the rules with no privileges at all — the one
 * shape a reader must never produce, because it is indistinguishable from an account that really
 * holds nothing.
 *
 * ## Why this is data and not a `match`
 *
 * A `match` in a reader is a list nobody reconciles. This file is reconciled by a test that asks a
 * REAL MySQL two questions the artifact cannot answer about itself: which privilege columns the
 * tables actually have (catching one nobody registered), and whether the server accepts each name in
 * a `GRANT` (catching one nobody can grant). The 8.4 vocabulary already moved once under this
 * package — the admin-privilege artifact was written with `SET_USER_ID`, which 8.4 refuses — so the
 * question is when it moves again, not whether.
 *
 * ## The unpivot is generated, and that is the point
 *
 * {@see self::unpivotExpression()} builds the `concat_ws` MySQL needs to turn a wide row into one
 * comma-joined privilege string. Generated from this artifact, the query and the mapping cannot
 * disagree; hand-written, they are two lists that drift and only one of them is ever read.
 *
 * ## Why the names are validated before they reach SQL
 *
 * The column is interpolated into a statement, so it is checked against a shape rather than
 * trusted: `[A-Za-z_]+`, which is what a grant-table column can be and nothing more. The privilege
 * name never reaches SQL at all — see {@see self::unpivotExpression()} — and is still checked,
 * because it reaches a FINDING a human reads and because the day somebody moves it back into a
 * query should not be the day the check is missing. The file ships inside the package and is not
 * user input, but "not user input today" is not a property string concatenation preserves.
 */
final readonly class MysqlStaticPrivileges
{
    /** The artifact format this reader implements; an unknown version is an error, never a default. */
    public const int SCHEMA_VERSION = 1;

    /** The one place the path lives, so a relocation is a single edit. */
    public const string BUNDLED_FILE = 'resources/data/mysql-static-privileges.json';

    /** The scope `mysql.user` answers for: privileges that apply to every database on the server. */
    public const string SCOPE_GLOBAL = 'global';

    /** The scope `mysql.db` answers for: privileges granted on one database. */
    public const string SCOPE_DATABASE = 'database';

    /** @param  list<MysqlStaticPrivilege>  $entries */
    private function __construct(
        public string $referenceServer,
        public array $entries,
    ) {}

    /**
     * The bundled artifact, parsed once per process.
     *
     * One parse rather than one per reading: the file is immutable while a process runs, and the
     * grants query is built on the single-file fast path that promises sub-second turnaround.
     */
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

        self::allowOnly($data, ['schema_version', 'reference_server', 'about', 'entries'], $origin, 'the artifact');

        $entries = [];
        $seen = [];

        foreach (self::listOf($data, 'entries', $origin) as $raw) {
            if (! is_array($raw)) {
                throw InvalidRuleEvidence::malformed($origin, 'entries', 'each entry an object');
            }

            /** @var array<string, mixed> $raw */
            $entry = self::entry($raw, $origin);

            if (isset($seen[$entry->column])) {
                throw InvalidRuleEvidence::malformed($origin, 'entries', "one entry per column — \"{$entry->column}\" appears more than once");
            }

            $seen[$entry->column] = true;
            $entries[] = $entry;
        }

        // An artifact with no entries would make the generated unpivot select nothing, which is
        // exactly the silence this whole class exists to end — and it would do it without an error.
        if ($entries === []) {
            throw InvalidRuleEvidence::malformed($origin, 'entries', 'at least one entry — an artifact with none reads no privileges at all');
        }

        return new self(self::str($data, 'reference_server', $origin), $entries);
    }

    /**
     * The entries that carry a privilege at this scope AND are read as ordinary privileges.
     *
     * An entry with `lifted_to` set is deliberately excluded: `Grant_priv` becomes the grant's own
     * `grantable` flag, and emitting it here as well would report one fact twice — once as a flag
     * and once as a privilege named `GRANT OPTION`.
     *
     * @return list<MysqlStaticPrivilege>
     */
    public function unpivoted(string $scope): array
    {
        return array_values(array_filter(
            $this->entries,
            static fn (MysqlStaticPrivilege $entry): bool => $entry->liftedTo === null && $entry->appliesTo($scope),
        ));
    }

    /**
     * Every column this artifact registers for a scope, whether lifted or not.
     *
     * The reconciliation test compares this against the server's own column list, so a lifted column
     * must appear — it IS registered, just read through another path, and leaving it out here would
     * make the test demand an entry that already exists.
     *
     * @return list<string>
     */
    public function columns(string $scope): array
    {
        return array_values(array_map(
            static fn (MysqlStaticPrivilege $entry): string => $entry->column,
            array_filter($this->entries, static fn (MysqlStaticPrivilege $entry): bool => $entry->appliesTo($scope)),
        ));
    }

    /**
     * The privilege a token from {@see self::unpivotExpression()} stands for, or null for anything
     * else.
     *
     * The unpivot emits COLUMN names, so the collector needs this to get back to the privilege. Null
     * rather than a fallback: the same collector also sees real privilege names from the SET columns
     * and from `mysql.global_grants`, and a lookup that guessed at those would rename them.
     *
     * The two vocabularies cannot collide — every grant-table column ends in `_priv` and no MySQL
     * privilege does — and an arm in the unit file holds that apart rather than leaving it to the eye.
     */
    public function privilegeFor(string $token): ?string
    {
        foreach ($this->entries as $entry) {
            if ($entry->column === $token) {
                return $entry->privilege;
            }
        }

        return null;
    }

    /**
     * A MySQL expression turning one wide grant-table row into a comma-joined list of the COLUMNS
     * that are set.
     *
     * `concat_ws` skips NULL arguments, so an `if(<column> = 'Y', '<column>', null)` per privilege
     * yields exactly the ones the account holds, in artifact order, with no trailing separator to
     * strip. An account with none produces the empty string — which the caller drops, because a row
     * per account regardless would invent a grant for every account on the server.
     *
     * One expression over one scan, rather than one UNION arm per privilege: `mysql.user` has thirty
     * of them, and thirty scans of the same small table is thirty chances to read it in thirty
     * different states.
     *
     * ## Why it emits the COLUMN name and not the privilege
     *
     * Because the privilege names are English, and MySQL's table-locking one is spelled exactly the
     * way the statement that takes such a lock is. Putting it in a query — even inside quotes —
     * makes a pure read look like a locking statement to the reader-harmlessness audit that scans
     * everything this package sends, and it caught exactly that on the first run.
     *
     * The audit is right to be suspicious of the words and wrong only about this one string. So the
     * fix is to keep them out of the SQL rather than teach the guard an exception: a guard with an
     * exception is a guard with a hole, and this one holds up the promise that SQLens never takes a
     * lock of its own on somebody's production database.
     *
     * The column name is already in the statement as an identifier, so emitting it as a literal adds
     * no token that was not there — and {@see self::privilegeFor()} translates on the way back.
     */
    public function unpivotExpression(string $scope): string
    {
        $terms = array_map(
            static fn (MysqlStaticPrivilege $entry): string => sprintf("if(%s = 'Y', '%s', null)", $entry->column, $entry->column),
            $this->unpivoted($scope),
        );

        // No entries for a scope would make `concat_ws` a syntax error rather than an empty result,
        // which is the wrong failure: it would read as a broken query instead of an empty artifact.
        if ($terms === []) {
            return "''";
        }

        return "concat_ws(',', ".implode(', ', $terms).')';
    }

    /** @param  array<string, mixed>  $data */
    private static function entry(array $data, string $origin): MysqlStaticPrivilege
    {
        self::allowOnly($data, ['column', 'privilege', 'scopes', 'lifted_to'], $origin, 'an entry');

        $column = self::str($data, 'column', $origin);

        // Interpolated into SQL, so the shape is asserted rather than assumed. MySQL identifiers can
        // hold far more than this; a grant-table privilege column cannot, and the narrow rule is what
        // makes the interpolation safe to read.
        if (preg_match('/^[A-Za-z_]+$/', $column) !== 1) {
            throw InvalidRuleEvidence::malformed($origin, 'column', 'a grant-table column name, letters and underscores only');
        }

        $privilege = self::str($data, 'privilege', $origin);

        // Upper-case words separated by single spaces — `CREATE TEMPORARY TABLES`, never a quote.
        if (preg_match('/^[A-Z]+( [A-Z]+)*$/', $privilege) !== 1) {
            throw InvalidRuleEvidence::malformed($origin, 'privilege', 'an upper-case MySQL privilege name, single spaces only');
        }

        $scopes = [];

        foreach (self::listOf($data, 'scopes', $origin) as $scope) {
            if ($scope !== self::SCOPE_GLOBAL && $scope !== self::SCOPE_DATABASE) {
                throw InvalidRuleEvidence::malformed($origin, 'scopes', 'each scope either global or database');
            }

            $scopes[] = $scope;
        }

        if ($scopes === []) {
            throw InvalidRuleEvidence::malformed($origin, 'scopes', 'at least one scope — an entry read at none is read nowhere');
        }

        $lifted = $data['lifted_to'] ?? null;

        if ($lifted !== null && (! is_string($lifted) || $lifted === '')) {
            throw InvalidRuleEvidence::malformed($origin, 'lifted_to', 'null, or the non-empty name of the field this column becomes');
        }

        return new MysqlStaticPrivilege($column, $privilege, $scopes, $lifted);
    }

    /**
     * @param  array<string, mixed>  $data
     * @param  list<string>  $allowed
     */
    private static function allowOnly(array $data, array $allowed, string $origin, string $what): void
    {
        foreach (array_keys($data) as $key) {
            if (! in_array($key, $allowed, true)) {
                throw InvalidRuleEvidence::malformed($origin, (string) $key, "not a known field of {$what}");
            }
        }
    }

    /** @param  array<string, mixed>  $data */
    private static function str(array $data, string $key, string $origin): string
    {
        $value = $data[$key] ?? null;

        if (! is_string($value) || $value === '') {
            throw InvalidRuleEvidence::malformed($origin, $key, 'a non-empty string');
        }

        return $value;
    }

    /**
     * @param  array<string, mixed>  $data
     * @return list<mixed>
     */
    private static function listOf(array $data, string $key, string $origin): array
    {
        $value = $data[$key] ?? null;

        if (! is_array($value) || ! array_is_list($value)) {
            throw InvalidRuleEvidence::malformed($origin, $key, 'a list');
        }

        return $value;
    }
}
