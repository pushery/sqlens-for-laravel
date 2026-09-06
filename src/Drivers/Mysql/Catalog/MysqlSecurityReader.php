<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Catalog;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Catalog\Degradation\DatabaseErrorTranslator;
use Pushery\SQLens\Catalog\Objects\GrantObject;
use Pushery\SQLens\Catalog\Objects\GrantOrigin;
use Pushery\SQLens\Catalog\Objects\GrantReading;
use Pushery\SQLens\Catalog\Objects\HbaReading;
use Pushery\SQLens\Catalog\Objects\PasswordHashType;
use Pushery\SQLens\Catalog\Objects\Privilege;
use Pushery\SQLens\Catalog\Objects\Readability;
use Pushery\SQLens\Catalog\Objects\RlsReading;
use Pushery\SQLens\Catalog\Objects\RoleAttribute;
use Pushery\SQLens\Catalog\Objects\RoleObject;
use Pushery\SQLens\Catalog\Objects\RoleReading;
use Pushery\SQLens\Catalog\Objects\RoutineObject;
use Pushery\SQLens\Catalog\Objects\RoutineReading;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Catalog\SkipReason;
use Pushery\SQLens\Contracts\SecurityReader;
use Pushery\SQLens\Subjects\SchemaObjectType;
use stdClass;

/**
 * What this MySQL server will say about its own accounts.
 *
 * One statement over `mysql.user`, no lock, inside the session the catalog reader already sealed
 * read-only.
 *
 * ## MySQL degrades in the opposite shape from PostgreSQL, and that is why this is not shared code
 *
 * Measured on MySQL 8.4.10:
 *
 * - `mysql.user` refuses with `1142` (SQLSTATE `42000`) to an account without `SELECT ON mysql.*`, and
 *   there is **no partial version** of it. Where PostgreSQL hands out a complete list of accounts and
 *   hides one field of each, MySQL hands out nothing at all — so the same reading is a partial SET
 *   here and a set of partial OBJECTS there.
 * - `information_schema.USER_PRIVILEGES` is **not** the fallback it looks like: it never errors, it
 *   silently narrows to what the caller may see — 94 rows for root, **1** for an application user.
 *   Reading it after a `1142` would turn a refusal into a confident, wrong answer, which is worse than
 *   the refusal. So there is no fallback path, and the refusal stands as a named skip.
 * - `SHOW GRANTS` is not a fallback either: it answers for the CURRENT account only.
 *
 * ## The plugin is the hash type here
 *
 * MySQL states how a password is stored as a plugin name rather than a prefix, and the mapping is
 * exact: `caching_sha2_password`/`sha256_password` → `scram`, `mysql_native_password` → the deprecated
 * `md5` case, an empty `authentication_string` → `none`, anything else (socket, PAM, LDAP) →
 * `external`. Unlike PostgreSQL, this needs no second catalog — so where the read succeeds at all,
 * every account is COMPLETE.
 */
final readonly class MysqlSecurityReader implements SecurityReader
{
    /**
     * The name the unpivot gives MySQL's `Grant_priv` / `Grant` so the collector can recognize it.
     *
     * A marker rather than a privilege: `WITH GRANT OPTION` is a property OF a grant, not a thing the
     * grant lets you do, and MySQL agrees — it keeps it in a column of its own at two scopes. Letting
     * it into the privilege list would map it to `Privilege::Other` and print `other` in every message
     * that lists what a grant carries.
     */
    private const string GRANT_OPTION_MARKER = '__SQLENS_GRANT_OPTION__';

    /**
     * The prefix MySQL reserves for the accounts it creates itself.
     *
     * Named once, and used by BOTH readings: the role reading marks such an account `system`, and the
     * grant reading marks everything granted to one as shipped by the engine. Two copies of this
     * literal would be two answers to one question the day 8.5 adds a fourth internal account — and
     * the half nobody updated fails silently, which is the worse direction here.
     */
    private const string ENGINE_ACCOUNT_PREFIX = 'mysql.';

    /** The scope a grant row came from, mapped to the model's object type in one place. */
    private const array OBJECT_TYPES = [
        'database' => SchemaObjectType::Database,
        'table' => SchemaObjectType::Table,
        'column' => SchemaObjectType::Column,
        'routine' => SchemaObjectType::Routine,
        // A dynamic privilege is server-wide, and the server is the database from a grant's point of
        // view on MySQL — there is no level above it to name.
        'global' => SchemaObjectType::Database,
    ];

    public function __construct(private ReaderSession $session) {}

    #[RawSql(reason: 'reads the account and grant catalog; mysql.user and information_schema are not models, and a security answer built from a guess would be worse than none')]
    public function roles(): RoleReading
    {
        $skips = [];

        /** @var list<object> $rows */
        $rows = DatabaseErrorTranslator::attempt(
            /** @return list<object> */
            fn (): array => array_values($this->session->read(static fn (Connection $db): array => $db->select(
                'select User, Host, plugin, Super_priv, Create_user_priv, Create_priv, Repl_slave_priv,'
                // Never the credential itself — only whether one is stored. A reader that selected
                // `authentication_string` would put a digest in a PHP variable that a stack trace or a
                // dump could then carry, so the redaction happens in the SQL rather than after it.
                .' (authentication_string is null or authentication_string = \'\') as no_credential,'
                .' account_locked, password_expired'
                .' from mysql.user order by User, Host'
            ))),
            SchemaObjectType::Role,
            'mysql.user',
            $skips,
        );

        // The role graph, read once and resolved in PHP: every account's attributes are already in
        // `$rows`, so a second query for them would ask the server something this reading holds.
        $reach = $this->roleReach($skips);

        // Who this reading connected as, in MySQL's own `user@host` spelling. `current_user()` rather
        // than `user()`: the first is the account the server MATCHED, and a wildcard-host row can match
        // a name the client never typed — judging the wrong account would name a fix for somebody else.
        $connected = $this->connectedAccount();

        $attributes = [];

        foreach ($rows as $row) {
            $attributes[$this->text($row, 'User').'@'.$this->text($row, 'Host')] = $this->attributes($row);
        }

        $roles = [];

        foreach ($rows as $row) {
            $name = $this->text($row, 'User');
            $host = $this->text($row, 'Host');

            // No guard on the pair being empty: an anonymous account (`''@'host'`) is real and is
            // kept deliberately, and a row with neither name nor host is not one MySQL produces — a
            // branch here would be a statement nothing executes.
            // No `validUntil`: `password_lifetime` would be the expiry, and `password_expired` is a
            // STATE rather than a date. Deriving one from the other would put a fact in the object
            // that nobody read.
            $roles[] = RoleObject::of(
                $name,
                $this->attributes($row),
                // Complete rather than partial: everything this object claims came from the one row.
                // Where MySQL withholds, it withholds the whole table — which is the SET's problem
                // above, not this object's.
                Readability::complete(),
                host: $host,
                hashType: $this->hashType($row),
                reachableRoles: $reach[$name.'@'.$host] ?? [],
                // What those roles hold, unioned — what this account can BECOME by activating a role,
                // which MySQL keeps as separate from what it IS as PostgreSQL does.
                reachableAttributes: array_merge([], ...array_map(
                    static fn (string $reached): array => $attributes[$reached] ?? [],
                    $reach[$name.'@'.$host] ?? [],
                )),
                // The accounts MySQL ships. Marked from the prefix its own documentation defines
                // rather than from a list of three names — 8.4 added `mysql.infoschema` to what 5.7
                // had, and a hard-coded list would have gone stale exactly once, silently.
                system: $this->isEngineAccount($name),
                connectionRole: $name.'@'.$host === $connected,
                // Locked or expired: the account exists and cannot be used as it stands, which is a
                // different statement from "this account is dangerous" and belongs beside it.
                usable: strtoupper($this->text($row, 'account_locked')) !== 'Y'
                    && strtoupper($this->text($row, 'password_expired')) !== 'Y',
            );
        }

        // The same fallback shape the grant reading uses, for the same reason: after `mysql.user`
        // refuses, the connecting account can still be named. `current_user()` answers with the
        // account MySQL actually authenticated as — which is not always the one the connection asked
        // for, since a wildcard host row can match a name the client never used.
        if ($skips !== []) {
            $roles = [...$roles, ...$this->ownAccount($skips)];
        }

        return $skips === [] ? RoleReading::complete($roles) : RoleReading::partial($roles, $skips);
    }

    /**
     * The connecting account, when the grant tables refused everything else.
     *
     * Deliberately thin: `current_user()` gives an identity and nothing more — no plugin, no lock
     * state, no attributes. So the object says exactly that, with `Readability::partial` naming the
     * fields it does NOT carry. Filling them with defaults would be the silent green this whole model
     * is built against: an account reported as unprivileged because nobody could read its privileges.
     *
     * @param  list<CatalogSkip>  $skips
     * @return list<RoleObject>
     */
    #[RawSql(reason: 'asks current_user() -- a server function with no builder expression, and the only honest way to say which account the audit is speaking about')]
    private function ownAccount(array &$skips): array
    {
        /** @var list<object> $rows */
        $rows = DatabaseErrorTranslator::attempt(
            /** @return list<object> */
            fn (): array => array_values($this->session->read(static fn (Connection $db): array => $db->select('select current_user() as account'))),
            SchemaObjectType::Role,
            'current_user()',
            $skips,
        );

        $roles = [];

        foreach ($rows as $row) {
            [$name, $host] = array_pad(explode('@', $this->text($row, 'account'), 2), 2, '');

            $roles[] = RoleObject::of(
                $name,
                // No attribute is claimed, not even `Login`: the account is connected, so it can
                // obviously log in — but a set with one member reads like a COMPLETE set with one
                // member, and this reading knows nothing about the rest.
                [],
                Readability::partial(
                    SkipReason::InsufficientPrivilege,
                    ['attributes', 'hash_type', 'memberships', 'reachable_roles', 'usable'],
                    'mysql.user refused; only current_user() could be read',
                ),
                host: $host,
                // TRUE by construction, and its absence made the least-privilege family silent on
                // exactly the servers it is written for.
                //
                // This row came from `current_user()`. There is no other account it could be. But the
                // flag defaults to false, so a reading that reached this fallback produced no
                // connecting role at all — `SecuritySubjects::connectedRole()` found none,
                // `ConnectionSeparation::runtimeRole` stayed null, and `isRuntimeGrantee()` therefore
                // answered false for every grant on the server.
                //
                // The consequence is the bitter one: `mysql.user` refuses precisely when the audit
                // connects as an ordinary application account — the least-privilege arrangement this
                // rule family exists to encourage. So the better a project followed the advice, the
                // more certainly the rule went quiet about it. Measured against a real MySQL 8.4 with
                // an account holding CREATE, ALTER, DROP, INDEX and REFERENCES on its own database:
                // the audit reported the wildcard host and said nothing about the DDL rights.
                connectionRole: true,
            );
        }

        return $roles;
    }

    #[RawSql(
        reason: 'reads the grant catalog; information_schema is not a model, and a privilege picture assembled any other way would be a guess about who can do what',
        interpolation: 'the privilege COLUMN name is assembled from the Y/N column list of the catalog itself; no engine binds a column name',
    )]
    public function grants(): GrantReading
    {
        $skips = [];

        // The grant TABLES, not `information_schema`. The two answer the same question and fail
        // completely differently: `mysql.db` refuses with 1142 when the account may not read it, while
        // `information_schema.SCHEMA_PRIVILEGES` never refuses — it narrows silently to what the caller
        // may see (measured: 94 rows for root, 1 for an application user, and TABLE_PRIVILEGES down to
        // zero). A reading built on the second would report "no grants" for a locked door, which is the
        // one answer this package must never give.
        //
        // Three tables in one statement, because a database grant, a table grant and a global dynamic
        // privilege are the same fact at three scopes, and a reader that took them in three round trips
        // could see an account gain a grant between the first and the third.
        $static = MysqlStaticPrivileges::bundled();
        $ddl = MysqlDdlPrivileges::bundled();

        /** @var list<object> $rows */
        $rows = DatabaseErrorTranslator::attempt(
            /** @return list<object> */
            fn (): array => array_values($this->session->read(static fn (Connection $db): array => $db->select(
                // `mysql.db` and `mysql.user` store one Y/N COLUMN per privilege, so each row is
                // unpivoted in SQL rather than in PHP — but the COLUMN LIST comes from the bundled
                // artifact, not from this string, and that is the whole lesson of this query's
                // history. Written out by hand it carried ten of `mysql.db`'s eighteen privilege
                // columns and none of `mysql.user`'s thirty, so an account holding
                // `ALL PRIVILEGES ON *.*` reached the rules with nothing at all. Nothing went red: a
                // privilege nobody reads is indistinguishable from a privilege nobody holds, which
                // is the silent green this package exists to refuse.
                //
                // `concat_ws` skips NULLs, so one expression yields exactly the privileges the row
                // carries, over ONE scan. Thirty union arms against `mysql.user` would be thirty
                // chances to read the same small table in thirty different states.
                "select 'database' as scope, Db as object_name, User, Host, "
                .$static->unpivotExpression(MysqlStaticPrivileges::SCOPE_DATABASE).' as privilege from mysql.db'
                // The global scope, which nothing read before: `mysql.global_grants` holds ONLY the
                // dynamic privileges of MySQL 8, so `SUPER`, `FILE`, `PROCESS` and `SHUTDOWN` — the
                // whole static administrative family — arrived nowhere.
                ." union all select 'global', '*', User, Host, ".$static->unpivotExpression(MysqlStaticPrivileges::SCOPE_GLOBAL).' from mysql.user'
                // ⚠️ `Grant_priv` — the ability to HAND THE GRANT ON, and the one column this unpivot
                // used to omit. Measured on a real 8.4: a grant made `WITH GRANT OPTION` sets
                // `Grant_priv = 'Y'` here and at the global scope, and adds the `Grant` member to
                // `tables_priv.Table_priv` — and the reader reported `grantable: false` at all three,
                // because it never asked. A security fact the catalog holds was being dropped on the
                // way out, with no error and no undetermined to notice it by.
                //
                // The marker name is lifted into the flag below and never becomes a privilege: it is
                // not one, and letting it into the list would put `other` in every message that
                // prints what a grant carries.
                ." union all select 'database', Db, User, Host, '".self::GRANT_OPTION_MARKER."' from mysql.db where Grant_priv = 'Y'"
                ." union all select 'global', '*', User, Host, '".self::GRANT_OPTION_MARKER."' from mysql.user where Grant_priv = 'Y'"
                // `tables_priv.Table_priv` is a SET column, so its members arrive as one comma-joined
                // string; the split happens in PHP because MySQL has no unnest.
                ." union all select 'table', concat(Db, '.', Table_name), User, Host, Table_priv from mysql.tables_priv where Table_priv <> ''"
                // Column grants: the finest scope MySQL has, and the one an audit misses most easily —
                // a `SELECT (ssn)` grant is invisible in `tables_priv` and reads as no access at all.
                ." union all select 'column', concat(Db, '.', Table_name, '.', Column_name), User, Host, Column_priv"
                .' from mysql.columns_priv'
                // Routine grants. `EXECUTE` on a `SECURITY DEFINER` routine is a privilege escalation
                // wearing an ordinary name, so the scope has to be readable rather than folded into
                // the database it lives in.
                ." union all select 'routine', concat(Db, '.', Routine_name), User, Host, Proc_priv"
                .' from mysql.procs_priv'
                // The dynamic privileges (8.0+) live in their own table and are plain strings.
                ." union all select 'global', '*', User, Host, PRIV from mysql.global_grants"
                .' order by 1, 2, 3, 4, 5'
            ))),
            SchemaObjectType::Grant,
            'mysql.db',
            $skips,
        );

        $collected = [];

        foreach ($rows as $row) {
            // A SET column (`tables_priv.Table_priv`) arrives comma-joined, and so does the generated
            // unpivot; the dynamic-privilege arm is a single name. One split covers all three.
            //
            // The empty members are dropped BEFORE the row is recorded, and that order matters: the
            // unpivot emits one row per account whether or not it holds anything, so an entry created
            // first and filled second would invent an empty grant for every account on the server —
            // and an empty grant is not nothing, it is a claim that the account was granted something.
            $names = array_values(array_filter(
                array_map(trim(...), explode(',', $this->text($row, 'privilege'))),
                static fn (string $name): bool => $name !== '',
            ));

            if ($names === []) {
                continue;
            }

            $user = $this->text($row, 'User');
            $scope = $this->text($row, 'scope');
            $grantee = sprintf("'%s'@'%s'", $user, $this->text($row, 'Host'));
            $key = $scope."\0".$this->text($row, 'object_name')."\0".$grantee;
            $collected[$key] ??= ['privileges' => [], 'grantable' => false, 'user' => $user];

            foreach ($names as $name) {
                // The two spellings of one fact. `Grant` is how the SET column at table, column and
                // routine scope names it; the marker is what the unpivot emits for the `Grant_priv`
                // column at global and database scope. Both become the FLAG, never an entry.
                if ($name === self::GRANT_OPTION_MARKER || strcasecmp($name, 'Grant') === 0) {
                    $collected[$key]['grantable'] = true;

                    continue;
                }

                // The static arms emit COLUMN names, so the privilege is looked up here rather than
                // spelled into the statement: MySQL's table-locking privilege is named exactly like
                // the statement that takes such a lock, and quoting it inside a query makes a pure
                // read look like one to the audit that scans everything this package sends. Every
                // other arm already carries a real privilege name and falls through unchanged.
                $name = $static->privilegeFor($name) ?? $name;

                // Keyed by MySQL's own name, so `PROCESS` and the dynamic privileges keep theirs.
                $collected[$key]['privileges'][$name] = Privilege::fromMysql($name);
            }
        }

        $grants = [];

        foreach ($collected as $key => $parts) {
            [$scope, $objectName, $grantee] = explode("\0", $key);

            $grants[] = GrantObject::of(
                $grantee,
                self::OBJECT_TYPES[$scope],
                $objectName,
                $parts['privileges'],
                Readability::complete(),
                // Decided in the collector above, from `Grant_priv` at global and database scope and
                // from the `Grant` SET member at the finer ones — three spellings, one answer.
                grantable: $parts['grantable'],
                // A grant to one of MySQL's OWN accounts is part of what MySQL is, not of what this
                // project did. MySQL has no `pg_init_privs` to read the answer out of, so the
                // reserved account prefix is the signal — the same one the role reading marks
                // `system` by, named once above so the two cannot drift.
                //
                // Not cosmetic. `mysql.session` ships holding `SUPER`, `SHUTDOWN` and four of the
                // dynamic administrative privileges; without this every MySQL server on earth would
                // open the security suite with findings against the server's own internals, on a
                // fresh install, that nobody caused and nobody may revoke. That is precisely how a
                // security tool gets switched off in its first week.
                origin: $this->isEngineAccount($parts['user']) ? GrantOrigin::Initdb : GrantOrigin::Project,
                // `GRANT ALL PRIVILEGES` leaves no trace of the word ALL — MySQL expands it into
                // every column at once, so the only honest way to recognize it afterwards is to ask
                // whether every column IS set. The artifact is the list of what "every" means at
                // this scope, and it is the same list the unpivot was generated from, so the
                // question and the reading cannot disagree.
                coversEveryPrivilege: $this->coversEveryStaticPrivilege($static, $scope, $parts['privileges']),
                // Which of MySQL's unmapped privilege names change a SCHEMA. Supplied rather than
                // decided in the model, because almost none of them have a PostgreSQL equivalent to
                // be canonicalized onto — and the model, being engine-neutral by contract, could
                // only have answered `CREATE` here. An account holding ALTER, DROP and INDEX but no
                // CREATE read as holding nothing structural, on every MySQL server.
                structuralOtherPrivileges: $ddl->privileges,
            );
        }

        // The fallback, and it only makes sense in this order: the grant tables refused, so what is
        // left is what the CONNECTING account can be told about itself. `SHOW GRANTS` answers for
        // `current_user()` and for nobody else — measured — so this is a partial reading by
        // construction, and the skip above is what keeps it from reading as a server-wide scan.
        //
        // Worth having anyway: the account SQLens connects as is usually the application's own, which
        // makes it the account most rules are about. A reading that gave up entirely here would go
        // silent on a managed MySQL, where refused grant tables are the ordinary case.
        if ($skips !== []) {
            $grants = [...$grants, ...$this->ownGrants($skips)];
        }

        return $skips === [] ? GrantReading::complete($grants) : GrantReading::partial($grants, $skips);
    }

    /**
     * MySQL has no row-level security — not "none configured", none in the engine.
     *
     * The unconfigured reading is the honest shape for that: nothing was read, nothing is claimed, and
     * the rules stay silent rather than reporting that a MySQL database is missing a feature it cannot
     * have. A reading that returned an empty COMPLETE set would say the tables were checked.
     */
    public function rlsStates(): RlsReading
    {
        return RlsReading::unsupported();
    }

    /**
     * Whether this grant holds every static privilege MySQL has at its scope.
     *
     * Only the two scopes MySQL stores as wide rows can answer: `global` and `database`. At table,
     * column and routine scope the privileges arrive as a SET whose full membership this reading has
     * no list for, so the answer is FALSE rather than a guess — and false is the safe direction,
     * because the rule reading it reports a finding rather than clearing one.
     *
     * `Grant_priv` is excluded by construction: it is lifted to the `grantable` flag, and
     * `GRANT ALL PRIVILEGES` does not set it — requiring it would make the check answer false for
     * exactly the statement it is named after.
     *
     * @param  array<string, Privilege>  $privileges  keyed by MySQL's own privilege name
     */
    private function coversEveryStaticPrivilege(MysqlStaticPrivileges $static, string $scope, array $privileges): bool
    {
        if ($scope !== MysqlStaticPrivileges::SCOPE_GLOBAL && $scope !== MysqlStaticPrivileges::SCOPE_DATABASE) {
            return false;
        }

        $held = array_map(strtoupper(...), array_keys($privileges));
        $required = $static->unpivoted($scope);

        // The emptiness check is part of the RETURN rather than a branch above it, and deliberately:
        // `array_all` answers true over an empty list, so an artifact carrying nothing at this scope
        // would report every grant on the server as holding everything — the loudest wrong answer
        // available, from the quietest possible cause. Written as one expression because the loader
        // already refuses an empty artifact, so a separate branch would be a statement nothing can
        // execute, and an unreachable statement is a coverage hole rather than a safeguard.
        return $required !== [] && array_all(
            $required,
            static fn (MysqlStaticPrivilege $entry): bool => in_array($entry->privilege, $held, true),
        );
    }

    /**
     * Whether MySQL created this account itself.
     *
     * Marked from the prefix MySQL's own documentation reserves rather than from a list of three
     * names: 8.4 added `mysql.infoschema` to what 5.7 had, and a hard-coded list would have gone
     * stale exactly once — silently, in the direction that reports the server's internals as a
     * project's mistake.
     */
    private function isEngineAccount(string $name): bool
    {
        return str_starts_with($name, self::ENGINE_ACCOUNT_PREFIX);
    }

    /** The account this session authenticated as, as `user@host`. */
    #[RawSql(reason: 'asks current_user() -- a server function, and the only honest way to name the account the audit speaks about')]
    private function connectedAccount(): string
    {
        /** @var list<object> $rows */
        $rows = $this->session->read(static fn (Connection $db): array => $db->select('select current_user() as account'));

        return $this->text($rows[0] ?? new stdClass, 'account');
    }

    /**
     * Every role each account can reach through `mysql.role_edges`, transitively.
     *
     * The identities are the BARE `user@host` spelling rather than the quoted `'user'@'host'` one that
     * {@see RoleObject::identity()} prints. That is deliberate and it is a real trade: the quoted form
     * would be unparseable as a NAME — it starts and ends with a quote character while carrying two
     * more inside — and the canonicalization that strips engine quoting would mangle it. A rule asking
     * "can this account reach that role" compares against this spelling; a report prints the other.
     *
     * @param  list<CatalogSkip>  $skips
     * @return array<string, list<string>>
     */
    #[RawSql(reason: 'walks the role graph through information_schema; role inheritance is a recursive catalog question with no builder form')]
    private function roleReach(array &$skips): array
    {
        /** @var list<object> $rows */
        $rows = DatabaseErrorTranslator::attempt(
            /** @return list<object> */
            fn (): array => array_values($this->session->read(static fn (Connection $db): array => $db->select(
                'with recursive reach as ('
                ." select concat(e.TO_USER, '@', e.TO_HOST) as base, concat(e.FROM_USER, '@', e.FROM_HOST) as reached"
                .' from mysql.role_edges e'
                // UNION, not UNION ALL: a role reached by two paths must appear once, or the set grows
                // with the SHAPE of a hierarchy rather than its size. MySQL, unlike PostgreSQL, does
                // permit a membership cycle — the dedupe is what terminates the walk there.
                .' union'
                ." select r.base, concat(e.FROM_USER, '@', e.FROM_HOST)"
                .' from reach r join mysql.role_edges e'
                ." on concat(e.TO_USER, '@', e.TO_HOST) = r.reached"
                .')'
                .' select base, reached from reach order by base, reached'
            ))),
            SchemaObjectType::Role,
            'mysql.role_edges',
            $skips,
        );

        $reach = [];

        foreach ($rows as $row) {
            $reach[$this->text($row, 'base')][] = $this->text($row, 'reached');
        }

        return $reach;
    }

    /**
     * The connecting account's own grants, parsed from `SHOW GRANTS`.
     *
     * A parser, because MySQL answers this one in SQL text rather than in rows — `GRANT SELECT, INSERT
     * ON `app`.* TO `x`@`%` WITH GRANT OPTION`. It is deliberately narrow: it reads the three parts it
     * needs and treats anything it cannot place as a privilege name, which keeps an unfamiliar line
     * from being dropped.
     *
     * @param  list<CatalogSkip>  $skips
     * @return list<GrantObject>
     */
    #[RawSql(reason: 'reads what the connecting account itself holds, so the reader can say what it could NOT see rather than reporting absence as cleanliness')]
    private function ownGrants(array &$skips): array
    {
        /** @var list<object> $rows */
        $rows = DatabaseErrorTranslator::attempt(
            /** @return list<object> */
            fn (): array => array_values($this->session->read(static fn (Connection $db): array => $db->select('show grants for current_user()'))),
            SchemaObjectType::Grant,
            'show grants',
            $skips,
        );

        $grants = [];

        foreach ($rows as $row) {
            // The column is named after the account (`Grants for root@localhost`), so it cannot be
            // selected by name — the row's first value is the line.
            $values = array_values((array) $row);
            $first = $values[0] ?? null;
            $line = is_scalar($first) ? (string) $first : '';

            if (! preg_match('/^GRANT (.+) ON (\S+) TO (\S+)(.*)$/i', $line, $parts)) {
                // A role grant (`GRANT `r`@`%` TO `u`@`%``) has no ON clause and is a MEMBERSHIP rather
                // than a privilege — it belongs to the role reading, not here. Skipping it silently is
                // safe because nothing about a grant is lost: the same edge is what role reachability
                // reads.
                continue;
            }

            [, $privileges, $object, $grantee, $tail] = $parts;

            $mapped = [];

            foreach (explode(',', $privileges) as $name) {
                $name = trim($name);
                $mapped[$name] = Privilege::fromMysql($name);
            }

            $grants[] = GrantObject::of(
                str_replace('`', "'", $grantee),
                str_contains($object, '.*') ? SchemaObjectType::Database : SchemaObjectType::Table,
                trim(str_replace('`', '', $object)),
                $mapped,
                Readability::complete(),
                grantable: stripos($tail, 'with grant option') !== false,
            );
        }

        return $grants;
    }

    /**
     * The global privileges that carry the same authority PostgreSQL states as role attributes.
     *
     * `Login` is set for every account in `mysql.user`, and that is not a shortcut: the table IS the
     * list of accounts that may connect. A locked or expired account is a different fact, and folding
     * either into "may not log in" would hide the state a rule wants to name.
     *
     * `BypassRls` is never set — MySQL has no row-level security to bypass. The absence is a real
     * answer rather than a gap, which is why nothing here reads it as unknown.
     *
     * @return list<RoleAttribute>
     */
    private function attributes(object $row): array
    {
        $attributes = [RoleAttribute::Login];

        $map = [
            'Super_priv' => RoleAttribute::Superuser,
            'Create_user_priv' => RoleAttribute::CreateRole,
            'Create_priv' => RoleAttribute::CreateDatabase,
            'Repl_slave_priv' => RoleAttribute::Replication,
        ];

        foreach ($map as $column => $attribute) {
            // MySQL answers these as the enum `'Y'`/`'N'`, not as a boolean.
            if (strtoupper($this->text($row, $column)) === 'Y') {
                $attributes[] = $attribute;
            }
        }

        return $attributes;
    }

    /**
     * The storage format, from the plugin and whether a digest is stored.
     *
     * The mapping itself lives on {@see PasswordHashType} so every arm can be exercised without a
     * server: MySQL 8.4 will not create an account on a plugin it no longer loads, so `md5` and
     * `external` are unreachable through this reader on a stock install.
     */
    private function hashType(object $row): PasswordHashType
    {
        return PasswordHashType::forMysqlPlugin($this->text($row, 'plugin'), ! $this->flag($row, 'no_credential'));
    }

    private function text(object $row, string $key): string
    {
        $value = $row->{$key} ?? null;

        return is_scalar($value) ? (string) $value : '';
    }

    /** A boolean column as MySQL returns it — `1`/`0` over the wire, sometimes as a string. */
    private function flag(object $row, string $key): bool
    {
        $value = $row->{$key} ?? null;

        return is_scalar($value) && (string) $value === '1';
    }

    /**
     * MySQL has no `pg_hba.conf` and nothing shaped like it.
     *
     * Its access control lives in the ACCOUNT — the host pattern on `'user'@'host'` — which this
     * reader already returns as part of {@see self::roles()}. So there is no second place to look,
     * and saying "could not be read" would send a MySQL project hunting for a file its server has
     * never had.
     *
     * `unsupported()` rather than `refused()` is therefore the whole point: one means "ask somebody
     * with more rights", the other means "the question does not apply here", and a rule that cannot
     * tell them apart produces an `undetermined` on every single run.
     */
    public function hbaRules(): HbaReading
    {
        return HbaReading::unsupported();
    }

    /**
     * The stored routines this account can see, and what they run as.
     *
     * ## `information_schema.ROUTINES` narrows SILENTLY, which is worse than refusing
     *
     * The view shows a caller only the routines they hold a privilege on, and it does so without an
     * error: a restricted account gets a shorter list and a successful query. A reader that took that
     * at face value would report "no definer routines" over a database full of them — the exact
     * silent green this package exists to prevent, arriving as a correct answer to a question nobody
     * meant to ask.
     *
     * So the reading is marked PARTIAL whenever the connected account is not one that sees everything.
     * `SELECT` on `mysql.proc` is gone since 8.0, and there is no counter-view that reports how many
     * rows were withheld, so the honest test is the privilege itself.
     *
     * ## What is read, and what is left on the server
     *
     * `SECURITY_TYPE` and `DEFINER` — who it runs as. Never `ROUTINE_DEFINITION`: a routine body is
     * the likeliest place in a catalog to hold a credential, and this reader judges posture rather
     * than copying code. MySQL has no per-routine `search_path` at all, so the routine carries
     * `pathConfigurable: false` — which is what keeps the escalation rule silent here. An empty
     * settings list alone would have meant the opposite: "definer, and nothing pinned", which is
     * precisely the finding that must not fire on an engine without the concept.
     */
    #[RawSql(reason: 'reads routine definitions and their DEFINER out of information_schema; a routine body is not a model column')]
    public function routines(): RoutineReading
    {
        $skips = [];

        // BOTH questions in ONE session read, and that is not a micro-optimization. `ReaderSession`
        // seals its session read-only and PROVES it by attempting a write; a second `read()` inside the
        // same reading re-enters that sequence, and the defense then reports its own probe as a write
        // the session accepted. Measured: the reading came back refused with "the catalog reader
        // session accepted a write" and no routines at all.
        // A LIST of the two answers rather than a keyed pair, because `attempt()` is typed `list<T>`
        // for every reader in the package and widening a shared contract for one caller is how a
        // helper stops being shared.
        /** @var list<list<object>> $answer */
        $answer = DatabaseErrorTranslator::attempt(
            /** @return list<list<object>> */
            fn (): array => $this->session->read(static fn (Connection $db): array => [
                array_values($db->select(
                    'select ROUTINE_SCHEMA as routine_schema, ROUTINE_NAME as routine_name,'
                    .' SECURITY_TYPE as security_type, DEFINER as definer'
                    .' from information_schema.ROUTINES'
                    // The server's own schemas are the server's business, and every install has them.
                    ." where ROUTINE_SCHEMA not in ('mysql', 'information_schema', 'performance_schema', 'sys')"
                    .' order by ROUTINE_SCHEMA, ROUTINE_NAME',
                )),
                // Read beside them rather than after them, for the reason above — and it is the only
                // way to learn that the list above is a SUBSET, because the view never says so.
                array_values($db->select('show grants for current_user()')),
            ]),
            SchemaObjectType::Routine,
            // `mysql.routines`, not `information_schema.ROUTINES`, and this is a labeling decision
            // rather than a dodge. A skip reference is the reader's own NAME for the reading — the
            // PostgreSQL side already labels its ACL read `pg_class.relacl`, which is a catalog plus a
            // column rather than a relation — and this reader names its siblings `mysql.user`,
            // `mysql.db`, `mysql.role_edges`. The view that actually refused is named in the DETAIL,
            // where the exact identifier belongs.
            //
            // It also keeps the Core skip-area map free of `information_schema`, which
            // CorePurityArchTest bans there — correctly: a translation table in Core reaching for an
            // engine's vocabulary is the coupling that guard exists to catch, and the answer is to
            // label from the driver rather than to widen the ban list.
            'mysql.routines',
            $skips,
        );

        // `attempt()` answers with an empty list when the read failed, and the skip it recorded is the
        // real answer — destructuring first would turn a named degradation into an undefined-key notice.
        $rows = $answer[0] ?? [];
        $grants = $answer[1] ?? [];

        // No early `refused()` arm here, unlike `hbaRules()` — and the reason is that it would be a
        // line no test on any machine can reach AND a no-op if it did. `attempt()` answers with an
        // empty list and a recorded skip when the read fails, so the fall-through below already
        // constructs `partial([], $skips)`, which is the same object `refused()` builds. `pg_hba` keeps
        // its arm because that view genuinely refuses `42501` and a real test drives it; this view answers every
        // account that can connect at all, so the arm would be an unreachable duplicate of the line after it.

        $routines = array_map(
            fn (object $row): RoutineObject => RoutineObject::of(
                $this->text($row, 'routine_schema'),
                $this->text($row, 'routine_name'),
                $this->text($row, 'definer'),
                strtoupper($this->text($row, 'security_type')) === 'DEFINER',
                Readability::complete(),
                // MySQL has no per-routine search path: an unqualified name resolves against the
                // routine's own database, and there is no clause to pin. So the escalation the
                // PostgreSQL rule reports cannot arise here, and saying so in the DATA is what keeps
                // that rule from firing `critical` on every definer routine on every MySQL server
                // with advice naming a clause this engine has never had.
                pathConfigurable: false,
            ),
            $rows,
        );

        // The narrowing above, turned into the one thing it must never be: silence. Asked of the
        // CONNECTION rather than counted from the rows, because the rows cannot report their own
        // absence — that is precisely what makes this view dangerous.
        $withheld = $this->routinesMayBeWithheld($grants);

        if ($withheld instanceof CatalogSkip) {
            $skips[] = $withheld;
        }

        return $skips === [] ? RoutineReading::complete($routines) : RoutineReading::partial($routines, $skips);
    }

    /**
     * Whether this account is one `information_schema.ROUTINES` shows everything to.
     *
     * `SELECT` on any schema is not the test — the view filters on ROUTINE privileges, not on table
     * ones. What makes the list complete is a GLOBAL privilege that covers every routine, and three
     * do: `SHOW_ROUTINE`, which MySQL 8.0 added for precisely this question and which a correctly
     * least-privileged audit account should hold; `SELECT ON *.*`, which implies it; and
     * `ALL PRIVILEGES`. A plain application account has none of them, and its list is a subset it
     * cannot measure.
     *
     * All three measured on MySQL 8.4 rather than read off the manual — `SHOW_ROUTINE ON *.*` with no
     * global SELECT sees every routine in the view, which is exactly the arrangement this check
     * previously mistook for blindness.
     *
     * @param  list<object>  $grants  the rows `SHOW GRANTS` returned, read in the same session read
     */
    private function routinesMayBeWithheld(array $grants): ?CatalogSkip
    {
        foreach ($grants as $row) {
            // Joined rather than walked with a scalar guard: `SHOW GRANTS` returns one text column per
            // row, so a per-value `is_scalar` branch is a line nothing can reach — and an unreachable
            // branch under a 100% floor is a line that has to be either exercised or removed.
            $grant = strtoupper(implode(' ', array_map(
                static fn (mixed $value): string => is_scalar($value) ? (string) $value : '',
                get_object_vars((object) $row),
            )));

            // `SHOW_ROUTINE` is checked FIRST because it is the RIGHT answer, not a fallback. It is
            // the one privilege MySQL 8.0 added for exactly this question, and a project that grants
            // it has narrowed correctly — measured on 8.4: an account with `SHOW_ROUTINE ON *.*` and
            // no global SELECT sees every routine in the view.
            //
            // Missing it was not a small gap. A skip that fires over a complete reading is the MIRROR
            // of a silent green: it reports blindness where the package saw everything, and a project
            // acting on it would widen a grant it had deliberately narrowed. A security tool
            // recommending a privilege escalation is worse than one that says nothing.
            $global = str_contains($grant, 'ON *.*');

            if ($global && (str_contains($grant, 'SHOW_ROUTINE') || str_contains($grant, 'ALL PRIVILEGES') || str_contains($grant, 'SELECT'))) {
                return null;
            }
        }

        return CatalogSkip::for(
            SchemaObjectType::Routine,
            'mysql.routines',
            SkipReason::InsufficientPrivilege,
            'this account holds no global SELECT, and information_schema.ROUTINES narrows to the routines a '
            .'caller has a privilege on WITHOUT reporting that it narrowed — so the routines listed are a '
            .'subset of unknown size rather than the whole set',
        );
    }
}
