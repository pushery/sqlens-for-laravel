<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Catalog;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Catalog\Degradation\DatabaseErrorTranslator;
use Pushery\SQLens\Catalog\Objects\GrantObject;
use Pushery\SQLens\Catalog\Objects\GrantOrigin;
use Pushery\SQLens\Catalog\Objects\GrantReading;
use Pushery\SQLens\Catalog\Objects\HbaReading;
use Pushery\SQLens\Catalog\Objects\HbaRule;
use Pushery\SQLens\Catalog\Objects\PasswordHashType;
use Pushery\SQLens\Catalog\Objects\Privilege;
use Pushery\SQLens\Catalog\Objects\Readability;
use Pushery\SQLens\Catalog\Objects\RlsCommand;
use Pushery\SQLens\Catalog\Objects\RlsPolicy;
use Pushery\SQLens\Catalog\Objects\RlsReading;
use Pushery\SQLens\Catalog\Objects\RlsState;
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
 * What this PostgreSQL server will say about its own accounts.
 *
 * Two statements over world-readable catalogs, no lock, inside the session the catalog reader already
 * sealed read-only.
 *
 * ## The split between `pg_roles` and `pg_authid` is the whole design
 *
 * Measured on PostgreSQL 18.0:
 *
 * - `pg_roles` answers **in full to every role**, a plain application role included — attributes,
 *   membership, `rolvaliduntil`. So the account list is never the part that degrades.
 * - `pg_roles.rolpassword` is `********` for **everyone**, superuser included. It is not a value; it
 *   is a placeholder that would parse as one.
 * - `pg_authid` — where the real hash lives — refuses `42501` to `pg_monitor` and to
 *   `pg_read_all_settings`, and answers to `pg_read_all_data` (measured on 18.4, both directions). We do not ask for the latter: it grants
 *   SELECT on every table in the database, so it would trade the exact property this package sells
 *   for a retrospective check that `password_encryption` already covers going forward.
 *
 * The result is the case the readability field exists for: a COMPLETE set of PARTIAL objects. Every
 * role is here, and on a managed instance every one of them says `withheld` for its hash type rather
 * than `none` — because "we could not look" and "there is no password" are the same sentence with
 * opposite meanings, and only one of them is an incident.
 */
final readonly class PgsqlSecurityReader implements SecurityReader
{
    /**
     * Where a grant came from, as a letter.
     *
     * `i` and `e` are `pg_init_privs.privtype` verbatim, and anything not in this map is somebody's
     * own grant. `o` is this reader's own addition, because `pg_init_privs` carries no row for the
     * OWNER's entry — see {@see GrantOrigin::Owner} for why that absence made the owner of every
     * granted table look like a decision somebody made.
     */
    private const array ORIGINS = ['i' => GrantOrigin::Initdb, 'e' => GrantOrigin::Extension, 'o' => GrantOrigin::Owner];

    /** The catalog's own word for a kind, mapped to the model's object type in one place. */
    private const array OBJECT_TYPES = [
        'table' => SchemaObjectType::Table,
        'schema' => SchemaObjectType::Schema,
        'routine' => SchemaObjectType::Routine,
        'database' => SchemaObjectType::Database,
    ];

    public function __construct(private ReaderSession $session, private ConfigRepository $config) {}

    #[RawSql(reason: 'reads pg_roles; the role catalog is not a model, and a security answer built from a guess would be worse than none')]
    public function roles(): RoleReading
    {
        $skips = [];

        /** @var list<object> $rows */
        $rows = DatabaseErrorTranslator::attempt(
            /** @return list<object> */
            fn (): array => array_values($this->session->read(static fn (Connection $db): array => $db->select(
                'select r.rolname, r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolbypassrls,'
                .' r.rolcanlogin, r.rolreplication, r.rolinherit, r.rolvaliduntil,'
                // The memberships, aggregated server-side and ordered there too: two round trips
                // would make the pairing of a role and its memberships a coincidence of timing.
                .' coalesce((select array_agg(g.rolname order by g.rolname) from pg_auth_members m'
                .'   join pg_roles g on g.oid = m.roleid where m.member = r.oid), array[]::name[]) as memberships,'
                // OWNERSHIP, in the same statement for the same reason as the memberships above: it
                // is a property of the role, and a second round trip would make the pairing a
                // coincidence of timing.
                //
                // It is here at all because ownership is a DDL right for which NO GRANT EXISTS. An
                // owner may ALTER and DROP its tables outright; the privilege lives in
                // pg_class.relowner and appears in no grant row. A check that reads only grants sees
                // nothing and reports silence — indistinguishable from a role that holds nothing.
                //
                // `relkind in ('r','p')` — ordinary and partitioned tables. Not indexes, sequences or
                // TOAST tables, which are owned by whoever owns the table they belong to and would
                // multiply one fact into several. `nspname not like 'pg\_%'` excludes the catalog and
                // every TOAST schema in one predicate; the grants reading above names the two schemas
                // it excludes, and that form would let pg_toast through here.
                .' coalesce((select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace'
                ."   where c.relowner = r.oid and c.relkind in ('r', 'p')"
                ."   and n.nspname not like 'pg\\_%' and n.nspname <> 'information_schema'), 0) as owned_tables"
                .' from pg_roles r order by r.rolname'
            ))),
            SchemaObjectType::Role,
            'pg_roles',
            $skips,
        );

        // Asked once for the whole reading rather than per role: the answer is a property of the
        // CONNECTING role, so per-role probing would repeat one fact N times and invite the reader to
        // think it varied.
        $hashes = $this->hashTypes($skips);

        // Asked once for the whole reading, like the hash types: the closure is a property of the
        // membership graph, and re-running it per role would be N queries answering one question.
        $reachable = $this->reachability($skips);

        // Who this reading connected as. One extra round trip for the fact every role rule turns on:
        // they judge the AUDIT's own account, because every server ships a privileged one and a rule
        // reporting all of them would report `postgres` on a database created thirty seconds ago.
        $connected = $this->connectedRole();

        $roles = [];

        foreach ($rows as $row) {
            // No emptiness guard: `pg_roles.rolname` is the view's key and is never null or empty, so
            // a skip branch here would be a statement nothing executes.
            $name = $this->text($row, 'rolname');

            $hashType = $hashes[$name] ?? PasswordHashType::Withheld;

            $roles[] = RoleObject::of(
                $name,
                $this->attributes($row),
                // The one field this reading cannot get without a privilege we decline to require, so
                // it is named as withheld rather than defaulted. `Readability::partial` refuses to be
                // built without naming a field, which is what keeps this honest.
                $hashType === PasswordHashType::Withheld
                    ? Readability::partial(SkipReason::InsufficientPrivilege, ['hash_type'], 'pg_authid is superuser-only; pg_roles masks rolpassword as ********')
                    : Readability::complete(),
                memberships: $this->memberships($row),
                hashType: $hashType,
                validUntil: is_scalar($row->rolvaliduntil ?? null) ? (string) $row->rolvaliduntil : null,
                reachableRoles: $reachable['roles'][$name] ?? [],
                reachableAttributes: $reachable['attributes'][$name] ?? [],
                reachablePaths: $reachable['paths'][$name] ?? [],
                // PostgreSQL's predefined roles all carry the reserved `pg_` prefix, which the manual
                // states and the server enforces on creation — so this is a rule rather than a list.
                // Without it every role rule reports `pg_monitor` and its siblings on a fresh server.
                system: str_starts_with($name, 'pg_'),
                connectionRole: $name === $connected,
                // PostgreSQL has no lock flag; `rolvaliduntil` in the past is the closest thing, and it
                // is already on the object as a DATE. Deriving a boolean from it here would duplicate a
                // judgment a rule can make with more context.
                usable: true,
                // Counted in the same statement above. An integer rather than a boolean, because
                // "owns 47 tables" and "owns 1" are different sentences to a reader deciding whether
                // a role is the one their migrations run as.
                ownedTables: is_scalar($row->owned_tables ?? null) ? (int) $row->owned_tables : null,
            );
        }

        return $skips === [] ? RoleReading::complete($roles) : RoleReading::partial($roles, $skips);
    }

    #[RawSql(reason: 'reads the ACL columns of pg_class and friends; an ACL is a catalog array with no model equivalent')]
    public function grants(): GrantReading
    {
        $skips = [];

        // One statement over four catalogs rather than four statements: the four ACL columns answer
        // one question, and a reading spread over four round trips could see a schema created between
        // the first and the last — a grant list that never existed in that combination at any moment.
        //
        // `aclexplode()` rather than parsing the ACL text. The format (`grantee=privs/grantor`, `*`
        // marking a grantable one, an EMPTY grantee meaning PUBLIC) is a parser nobody should write
        // twice, and the server already has one. No privilege is needed for any of it: measured on
        // PostgreSQL 18, a plain application role sees exactly the ACLs a superuser does — which is
        // why this reading has no privilege pre-probe while the `pg_authid` one does. A probe that
        // can only ever pass is a ritual, not a check.
        /** @var list<object> $rows */
        $rows = DatabaseErrorTranslator::attempt(
            /** @return list<object> */
            fn (): array => array_values($this->session->read(static fn (Connection $db): array => $db->select(
                // Every arm carries the ORIGIN, read from `pg_init_privs` rather than guessed: it is the
                // ACL an object had when initdb finished or when the extension that owns it was
                // installed, which is exactly the question "did somebody here grant this". Matched on
                // the same (object, grantee, privilege) triple, so a project grant that happens to
                // repeat a default is still recognized as the default it repeats.
                'with init as ('
                .' select p.classoid, p.objoid, p.privtype, a.grantee, a.privilege_type'
                .' from pg_init_privs p, lateral aclexplode(p.initprivs) a where p.objsubid = 0'
                .')'
                ." select 'table' as kind, n.nspname||'.'||c.relname as object_name,"
                .' a.privilege_type, a.is_grantable, pg_get_userbyid(a.grantor) as grantor,'
                ." case when a.grantee = 0 then '' else pg_get_userbyid(a.grantee) end as grantee,"
                ." coalesce(i.privtype::text, case when a.grantee = c.relowner then 'o' end) as origin"
                .' from pg_class c join pg_namespace n on n.oid = c.relnamespace'
                // CROSS JOIN LATERAL rather than a comma: the LEFT JOIN below has to see `c`, and a
                // comma-joined item is out of scope for the join that follows it.
                .' cross join lateral aclexplode(c.relacl) a'
                ." left join init i on i.classoid = 'pg_class'::regclass and i.objoid = c.oid"
                .' and i.grantee = a.grantee and i.privilege_type = a.privilege_type'
                // The system catalogs' own ACLs are the server's, not the project's, and every install
                // has hundreds of them. Including them would bury the rows a reader can act on.
                ." where c.relacl is not null and n.nspname not in ('pg_catalog', 'information_schema')"
                .' union all'
                ." select 'schema', n.nspname, a.privilege_type, a.is_grantable, pg_get_userbyid(a.grantor),"
                ." case when a.grantee = 0 then '' else pg_get_userbyid(a.grantee) end,"
                ." coalesce(i.privtype::text, case when a.grantee = n.nspowner then 'o' end)"
                .' from pg_namespace n cross join lateral aclexplode(n.nspacl) a'
                ." left join init i on i.classoid = 'pg_namespace'::regclass and i.objoid = n.oid"
                .' and i.grantee = a.grantee and i.privilege_type = a.privilege_type'
                ." where n.nspacl is not null and n.nspname not in ('pg_catalog', 'information_schema')"
                .' union all'
                ." select 'routine', n.nspname||'.'||p.proname, a.privilege_type, a.is_grantable, pg_get_userbyid(a.grantor),"
                ." case when a.grantee = 0 then '' else pg_get_userbyid(a.grantee) end,"
                ." coalesce(i.privtype::text, case when a.grantee = p.proowner then 'o' end)"
                .' from pg_proc p join pg_namespace n on n.oid = p.pronamespace cross join lateral aclexplode(p.proacl) a'
                ." left join init i on i.classoid = 'pg_proc'::regclass and i.objoid = p.oid"
                .' and i.grantee = a.grantee and i.privilege_type = a.privilege_type'
                ." where p.proacl is not null and n.nspname not in ('pg_catalog', 'information_schema')"
                .' union all'
                // `pg_init_privs` does not cover databases, so the one default PostgreSQL ships there is
                // recognized by its shape instead: CONNECT and TEMPORARY to PUBLIC is what every
                // database is created with. Anything else on a database is somebody's decision.
                ." select 'database', d.datname, a.privilege_type, a.is_grantable, pg_get_userbyid(a.grantor),"
                ." case when a.grantee = 0 then '' else pg_get_userbyid(a.grantee) end,"
                ." case when a.grantee = 0 and a.privilege_type in ('CONNECT', 'TEMPORARY') then 'i'"
                ." when a.grantee = d.datdba then 'o' end"
                .' from pg_database d cross join lateral aclexplode(d.datacl) a'
                .' where d.datacl is not null'
                .' order by 1, 2, 6, 3'
            ))),
            SchemaObjectType::Grant,
            'pg_class.relacl',
            $skips,
        );

        // One grant per (object, grantee) with the privileges collected, rather than one row per
        // privilege: "app may SELECT and INSERT here" is one fact, and split across two objects every
        // rule would have to re-join them before it could ask anything.
        $collected = [];

        foreach ($rows as $row) {
            $key = $this->text($row, 'kind')."\0".$this->text($row, 'object_name')."\0".$this->text($row, 'grantee');
            $collected[$key] ??= ['privileges' => [], 'grantable' => false, 'grantor' => $this->text($row, 'grantor'), 'origins' => []];

            // Keyed by the catalog's own word for the privilege, so an unmapped one keeps its name
            // without a branch here deciding which ones deserve to. On PostgreSQL 18 every privilege
            // has a case, and a branch for the ones that do not would be a statement nothing executes
            // until PostgreSQL 19 adds one.
            $type = $this->text($row, 'privilege_type');
            $collected[$key]['privileges'][$type] = Privilege::fromPostgres($type);

            // Grantable at the GRANT level rather than per privilege: PostgreSQL records it per
            // privilege, and a grant where any one of them may be passed on is a grant that spreads.
            $collected[$key]['grantable'] = $collected[$key]['grantable'] || ($row->is_grantable ?? false) === true;

            // Collected per row and decided once below: a grant is one object here, but PostgreSQL
            // records an origin per PRIVILEGE, and the two can disagree on the same object.
            $collected[$key]['origins'][] = self::ORIGINS[$this->text($row, 'origin')] ?? GrantOrigin::Project;
        }

        $grants = [];
        $complete = $this->completePrivilegeSets();

        foreach ($collected as $key => $parts) {
            [$kind, $objectName, $grantee] = explode("\0", $key);

            $grants[] = GrantObject::of(
                $grantee,
                self::OBJECT_TYPES[$kind],
                $objectName,
                $parts['privileges'],
                Readability::complete(),
                grantor: $parts['grantor'],
                grantable: $parts['grantable'],
                origin: $this->strongestOrigin($parts['origins']),
                coversEveryPrivilege: $this->coversEveryPrivilege($complete, $kind, $parts['privileges']),
            );
        }

        return $skips === [] ? GrantReading::complete($grants) : GrantReading::partial($grants, $skips);
    }

    /**
     * What "every privilege" means on this server, per kind of object — asked of the server itself.
     *
     * `acldefault(objtype, owner)` is the ACL PostgreSQL gives a freshly created object of that type,
     * and the owner's entry in it is by definition every privilege the type permits. So the complete
     * set is READ rather than kept in a list here: `MAINTAIN` arrived in 17 and the next one will
     * arrive the same way, and a hand-kept list would then quietly stop recognizing `GRANT ALL`.
     *
     * A separate statement from the grants query, deliberately. That query is one round trip because
     * the grants it reads can change between two; this answers a property of the SERVER VERSION,
     * which cannot change under a session — so there is nothing here for a second read to race.
     *
     * Owner id `0` rather than a real one: `aclexplode` reports the owner's entry with grantee `0`,
     * and nothing here reads the grantee. Using an id that exists would only invite the reader to
     * think it mattered.
     *
     * @return array<string, list<string>> the reading's own kind => privilege names, upper-cased
     */
    #[RawSql(reason: 'compares held privileges against the complete set the engine defines, which only the catalog can enumerate')]
    private function completePrivilegeSets(): array
    {
        /** @var list<object> $rows */
        $rows = $this->session->read(static fn (Connection $db): array => $db->select(
            "select k.kind, string_agg(distinct a.privilege_type, ',') as privileges"
            ." from (values ('table', 'r'), ('schema', 'n'), ('routine', 'f'), ('database', 'd')) as k(kind, objtype)"
            .' cross join lateral aclexplode(acldefault(k.objtype::"char", 0)) a'
            .' group by k.kind'
        ));

        $sets = [];

        foreach ($rows as $row) {
            $sets[$this->text($row, 'kind')] = array_values(array_filter(
                array_map(strtoupper(...), explode(',', $this->text($row, 'privileges'))),
                static fn (string $name): bool => $name !== '',
            ));
        }

        return $sets;
    }

    /**
     * Whether this grant carries every privilege its object type permits.
     *
     * An unknown kind, or one the server answered nothing for, is FALSE rather than true — the
     * direction matters, because the rule reading this reports a finding on true. An empty required
     * set would otherwise make every grant on the server look like `GRANT ALL PRIVILEGES`.
     *
     * ## The sequence caveat, stated rather than hidden
     *
     * This reading folds every `pg_class` entry into one kind, so a sequence is compared against the
     * TABLE set — and a sequence's full set is `SELECT, UPDATE, USAGE`, which no table grant carries.
     * The comparison therefore answers false for a sequence granted everything. That is a miss, not a
     * wrong finding: the rule stays silent where it cannot be sure, which is the only direction a
     * security check may be imprecise in.
     *
     * @param  array<string, list<string>>  $complete
     * @param  array<string, Privilege>  $privileges  keyed by PostgreSQL's own privilege name
     */
    private function coversEveryPrivilege(array $complete, string $kind, array $privileges): bool
    {
        $required = $complete[$kind] ?? [];
        $held = array_map(strtoupper(...), array_keys($privileges));

        // The emptiness check rides in the return rather than guarding above it: `array_all` answers
        // true over an empty list, so a kind the server named nothing for would report every grant on
        // it as holding everything. One expression because the state cannot be reached through the
        // reader, and an unreachable branch is a coverage hole rather than a safeguard.
        return $required !== [] && array_all($required, static fn (string $name): bool => in_array($name, $held, true));
    }

    #[RawSql(reason: 'reads relrowsecurity and relforcerowsecurity from pg_class; row-level security state lives nowhere else')]
    public function rlsStates(): RlsReading
    {
        // The scope is the PROJECT's answer, and without one there is nothing to read. Reading every
        // table instead would produce a finding for every reference table, job queue and migration
        // ledger in the schema — a report nobody finishes, from a tool that has learned nothing about
        // the application.

        // `off` is read BEFORE the scope, and that ordering is the fix. Collecting first collapsed it
        // into the same empty list an unconfigured project produces, and from there nothing
        // downstream could tell the two apart — so a project that had done what the finding asked of
        // it got the finding again, at severity high, on every run.
        if ($this->config->get('sqlens.security.rls.mode') === 'off') {
            return RlsReading::declinedByConfig();
        }

        $tables = $this->rlsScope();

        if ($tables === []) {
            return RlsReading::unconfigured();
        }

        // An unqualified name is resolved the way the SERVER resolves one, and that is the whole of
        // this split. `security.rls.tables` used to match only against `schema.table`, so a consumer
        // who wrote `api_keys` — the name his own migration created the table under — got
        // `not found in the catalog` for every entry: fifteen skips over fifteen tables that exist,
        // with a message pointing at a missing table and a managed-instance hint that fitted the
        // symptom and not the cause. A security list matching NOTHING also reports nothing, so it
        // looked configured.
        //
        // `current_schema()` is not a guess about naming: it is the first existing entry of the
        // session's own search_path, which is exactly where an unqualified CREATE TABLE puts a table.
        // Both literals are built HERE rather than inside the query closure: that closure is `static`,
        // so `$this` does not exist in it and only what an arrow function captures is reachable.
        $qualifiedList = $this->textArray(array_values(array_filter($tables, static fn (string $t): bool => str_contains($t, '.'))));
        $bareList = $this->textArray(array_values(array_filter($tables, static fn (string $t): bool => ! str_contains($t, '.'))));

        $skips = [];

        /** @var list<object> $rows */
        $rows = DatabaseErrorTranslator::attempt(
            /** @return list<object> */
            fn (): array => array_values($this->session->read(static fn (Connection $db): array => $db->select(
                'select n.nspname||\'.\'||c.relname as table_name, c.relrowsecurity as enabled,'
                .' c.relforcerowsecurity as forced,'
                // The OWNER by name, resolved by the server rather than joined by hand: `relowner` is
                // an oid, and the rule that matters most here — the application connects as the role
                // that owns its tables — is a comparison against a NAME.
                .' pg_get_userbyid(c.relowner) as owner,'
                .' p.polname, p.polcmd, p.polpermissive,'
                // The EXPRESSIONS, deparsed by the server. `pg_get_expr` rebuilds the stored parse
                // tree, so `USING ( TRUE )`, `using(true)` and `USING (TRUE)` all come back as `true`
                // — measured. That is the canonicalization a rule would otherwise fake with a regex
                // over whatever somebody typed, done correctly because the server is printing the tree
                // it will actually evaluate.
                .' pg_get_expr(p.polqual, p.polrelid) as using_expr,'
                .' pg_get_expr(p.polwithcheck, p.polrelid) as check_expr,'
                // Role oid 0 is PUBLIC — the same pseudo-role a grant names, and the same reason it
                // cannot be left to a join that would simply find nothing.
                .' (select array_agg(r.rolname order by r.rolname) from pg_roles r'
                .'  where r.oid = any(p.polroles) and r.oid <> 0) as roles'
                .' from pg_class c join pg_namespace n on n.oid = c.relnamespace'
                .' left join pg_policy p on p.polrelid = c.oid'
                // Both kinds of table, and NO partitions. `relkind` is `r` for an ordinary table and
                // `p` for a PARTITIONED one — a filter on `r` alone silently drops every partitioned
                // table, which is exactly the kind of table a tenant schema uses. Measured: the
                // partition arm of the lane found nothing until `p` was added.
                //
                // Partitions themselves are judged at the parent: RLS is a property of the partitioned
                // table, and reporting n partitions would multiply one finding by however many exist.
                .' where c.relkind in (\'r\', \'p\') and c.relispartition = false'
                .' and (n.nspname||\'.\'||c.relname = any(?)'
                .' or (n.nspname = current_schema() and c.relname = any(?)))'
                .' order by 1, p.polname',
                [$qualifiedList, $bareList],
            ))),
            SchemaObjectType::Policy,
            'pg_policy',
            $skips,
        );

        $collected = [];

        foreach ($rows as $row) {
            $table = $this->text($row, 'table_name');
            $collected[$table] ??= [
                'enabled' => ($row->enabled ?? false) === true,
                'forced' => ($row->forced ?? false) === true,
                'owner' => $this->text($row, 'owner'),
                'policies' => [],
            ];

            $command = RlsCommand::fromCatalog($this->text($row, 'polcmd'));
            $name = $this->text($row, 'polname');
            // ONE decision, not two: this row is not a policy this build can judge. It is reached on
            // every table that HAS no policy — the LEFT JOIN yields a row with an empty name, which is
            // the fail-closed state and not a row to drop — and it would also catch a `polcmd` a later
            // PostgreSQL adds. Splitting it in two put the second half on a line nothing can execute,
            // which the coverage floor was right to call out.
            // Kept as a NAMED condition rather than as `if ($a || $b)`: Rector rewrites the second
            // form into two ifs, and the half that a live server never reaches then sits on a line
            // nothing executes — which the coverage floor is right to call out and which no test can
            // honestly close.
            $notAJudgeablePolicy = $name === '' || ! $command instanceof RlsCommand;

            if ($notAJudgeablePolicy) {
                continue;
            }

            $collected[$table]['policies'][] = RlsPolicy::of(
                $name,
                $command,
                ($row->polpermissive ?? true) === true,
                $this->memberships($row, 'roles'),
                $this->nullableText($row, 'using_expr'),
                $this->nullableText($row, 'check_expr'),
            );
        }

        $states = [];

        foreach ($collected as $table => $parts) {
            $states[] = RlsState::of($table, $parts['enabled'], $parts['forced'], $parts['policies'], Readability::complete(), $parts['owner']);
        }

        // A table the project named and the catalog does not have is a finding of its own kind — a
        // configuration that points at nothing — so it is a SKIP rather than a silent absence.
        //
        // A bare name reached the result set only through the `current_schema()` branch above, so
        // matching it back by its own bare half is exact rather than approximate. It gets its own
        // sentence too: `not found in the catalog` describes a missing table, and a reader who was
        // told that went looking for a typo or an unrun migration over a table that was there.
        $qualifiedFound = array_keys($collected);
        $bareFound = array_map(static fn (string $name): string => str_contains($name, '.') ? explode('.', $name, 2)[1] : $name, $qualifiedFound);

        foreach ($tables as $named) {
            if (in_array($named, $qualifiedFound, true)) {
                continue;
            }

            if (! str_contains($named, '.')) {
                if (in_array($named, $bareFound, true)) {
                    continue;
                }

                $skips[] = CatalogSkip::for(SchemaObjectType::Policy, $named, SkipReason::NotReadable, 'named in sqlens.security.rls.tables without a schema, and the current schema holds no table of that name; write it as schema.table if it lives in another one');

                continue;
            }

            $skips[] = CatalogSkip::for(SchemaObjectType::Policy, $named, SkipReason::NotReadable, 'named in sqlens.security.rls.tables, not found in the catalog');
        }

        return $skips === [] ? RlsReading::complete($states) : RlsReading::partial($states, $skips);
    }

    /**
     * A PostgreSQL text-array literal for a bound parameter.
     *
     * The quoting is not decoration: an entry carrying a `"` or a `\` would otherwise close the
     * literal early and the whole array would arrive as something else. These names come from a
     * project's own configuration file rather than from a request, so this is a correctness guard
     * rather than a boundary — but a literal built by concatenation is where that distinction stops
     * being visible to the next reader.
     *
     * @param  list<string>  $values
     */
    private function textArray(array $values): string
    {
        $escaped = array_map(
            static fn (string $value): string => str_replace(['\\', '"'], ['\\\\', '\\"'], $value),
            $values,
        );

        return '{"'.implode('","', $escaped).'"}';
    }

    /**
     * Which tables this reading covers, from the project's own configuration.
     *
     * `listed` takes the names as given; `heuristic` asks the catalog which tables carry the tenant
     * column, which is a question about THIS database rather than a guess about naming; `off` covers
     * nothing. An empty answer is what makes the reading unconfigured.
     *
     * @return list<string>
     */
    #[RawSql(reason: 'reads pg_policy to see what each policy actually restricts; a policy expression is catalog text, not a model column')]
    private function rlsScope(): array
    {
        $mode = $this->config->get('sqlens.security.rls.mode');

        if ($mode === 'heuristic') {
            $column = $this->config->get('sqlens.security.rls.tenant_column');

            if (! is_string($column) || $column === '') {
                return [];
            }

            /** @var list<object> $rows */
            $rows = $this->session->read(static fn (Connection $db): array => $db->select(
                'select n.nspname||\'.\'||c.relname as table_name'
                .' from pg_class c join pg_namespace n on n.oid = c.relnamespace'
                .' join pg_attribute a on a.attrelid = c.oid and a.attname = ? and a.attnum > 0 and not a.attisdropped'
                .' where c.relkind in (\'r\', \'p\') and c.relispartition = false'
                .' and n.nspname not in (\'pg_catalog\', \'information_schema\')'
                .' order by 1',
                [$column],
            ));

            return array_map(fn (object $row): string => $this->text($row, 'table_name'), $rows);
        }

        // The `listed` test rides in the EXPRESSION rather than as an early return, and that is the
        // coverage floor rather than style. `off` is answered in rlsStates() before this method is
        // reached and `heuristic` returned above, so the only value that could take an early return
        // here is a mode the config validator refuses outright — a branch no run can enter, and one
        // no test can honestly close. The behavior is unchanged: anything but `listed` reads null,
        // and null is not an array.
        $tables = $mode === 'listed' ? $this->config->get('sqlens.security.rls.tables') : null;

        return is_array($tables)
            ? array_values(array_filter(array_map(static fn (mixed $t): string => is_string($t) ? trim($t) : '', $tables), static fn (string $t): bool => $t !== ''))
            : [];
    }

    /**
     * Every role each account can reach through membership, and what those roles hold.
     *
     * A RECURSIVE closure, not one hop: `app` is a member of `deploy`, `deploy` is a member of
     * `admin`, and `app` can become `admin` in two steps that no single-hop reading shows.
     *
     * `union` rather than `union all`, and the reason is a diamond rather than a cycle: a role reached
     * by two paths would otherwise appear once per PATH, so the set would grow with the shape of the
     * hierarchy instead of with its size. Cycles are not the concern — measured, PostgreSQL 18 refuses
     * to create one at all (`0LP01: role "b" is a member of role "a"`).
     *
     * It is a separate statement from the role list on purpose: the closure multiplies rows, and
     * joining it into the main query would return one row per (role, reachable role) pair and make
     * every attribute arrive N times.
     *
     * @param  list<CatalogSkip>  $skips
     * @return array{roles: array<string, list<string>>, attributes: array<string, list<RoleAttribute>>, paths: array<string, array<string, string>>}
     */
    #[RawSql(reason: 'walks role membership recursively through pg_auth_members; inheritance has no builder form')]
    private function reachability(array &$skips): array
    {
        /** @var list<object> $rows */
        $rows = DatabaseErrorTranslator::attempt(
            /** @return list<object> */
            fn (): array => array_values($this->session->read(static fn (Connection $db): array => $db->select(
                // The PATH, not just the endpoint. A finding that says "this role reaches superuser"
                // and stops is not resolvable: the person fixing it has to know WHICH grant to revoke,
                // and on a three-step chain that is two grants they cannot see. So the walk carries the
                // roles it went through, and the SHORTEST path per pair survives — `distinct on` over
                // the length, because a diamond offers several and the shortest is the one a reader
                // acts on first.
                //
                // `union all` with an explicit cycle guard rather than `union`: the dedupe of `union`
                // works on the whole row, and two rows differing only in their path are not duplicates
                // to it — the walk would keep finding longer ways round. PostgreSQL refuses to CREATE a
                // membership cycle, but the guard costs one comparison and does not rely on that.
                'with recursive reach as ('
                .' select m.member as base, m.roleid as reached, array[m.roleid] as path'
                .' from pg_auth_members m'
                .' union all'
                .' select r.base, m.roleid, r.path || m.roleid from reach r'
                .' join pg_auth_members m on m.member = r.reached'
                .' where not m.roleid = any(r.path)'
                .')'
                .' select distinct on (reach.base, reach.reached)'
                .' b.rolname as base, g.rolname as reached,'
                .' g.rolsuper, g.rolcreaterole, g.rolcreatedb, g.rolbypassrls, g.rolcanlogin,'
                .' g.rolreplication, g.rolinherit,'
                // The path as names, in order, so the finding can print it verbatim.
                .' (select array_agg(p.rolname order by step.ord)'
                .'  from unnest(reach.path) with ordinality as step(oid, ord)'
                .'  join pg_roles p on p.oid = step.oid) as path'
                .' from reach join pg_roles b on b.oid = reach.base'
                .' join pg_roles g on g.oid = reach.reached'
                .' order by reach.base, reach.reached, array_length(reach.path, 1)'
            ))),
            SchemaObjectType::Role,
            'pg_auth_members',
            $skips,
        );

        $roles = [];
        $attributes = [];
        $paths = [];

        foreach ($rows as $row) {
            $base = $this->text($row, 'base');
            $reached = $this->text($row, 'reached');

            $roles[$base][] = $reached;
            $attributes[$base] = [...$attributes[$base] ?? [], ...$this->attributes($row)];
            // The membership that leads there, from the base role outwards. The base itself is not in
            // the catalog's path array — it is the row's own key — so it is prepended here, which is
            // what makes the printed chain read the way a person describes it.
            $paths[$base][$reached] = implode(' -> ', [$base, ...$this->memberships($row, 'path')]);
        }

        return ['roles' => $roles, 'attributes' => $attributes, 'paths' => $paths];
    }

    /**
     * The origin a collected grant reports when its privileges disagree.
     *
     * A project grant beside a default one on the same object makes the whole thing a project
     * decision, because somebody chose the part that is not standard. The reverse — calling it a
     * default because one of its privileges is — would hide exactly the privilege a reader needs to
     * see, which is the failure this field exists to prevent.
     *
     * @param  list<GrantOrigin>  $origins
     */
    private function strongestOrigin(array $origins): GrantOrigin
    {
        return in_array(GrantOrigin::Project, $origins, true)
            ? GrantOrigin::Project
            : (in_array(GrantOrigin::Extension, $origins, true) ? GrantOrigin::Extension : GrantOrigin::Initdb);
    }

    /** The role this session authenticated as — `current_user`, which SET ROLE moves. */
    #[RawSql(reason: 'asks current_user and session_user, the only honest way to name the role the audit speaks about')]
    private function connectedRole(): string
    {
        /** @var list<object> $rows */
        $rows = $this->session->read(static fn (Connection $db): array => $db->select('select current_user as who'));

        return $this->text($rows[0] ?? new stdClass, 'who');
    }

    /**
     * The hash type per role from `pg_authid`, or an empty map when the catalog refused.
     *
     * The refusal is the ORDINARY answer here, so it becomes a named skip and the caller marks every
     * role partial. What must never happen is the empty map being read as "no role has a password".
     *
     * The hash VALUE never leaves this method. Only its prefix is inspected, and only the resulting
     * enum travels — the redaction sits at the reader rather than at the reporter, so no later layer
     * has to remember to strip anything.
     *
     * @param  list<CatalogSkip>  $skips
     * @return array<string, PasswordHashType>
     */
    #[RawSql(reason: 'reads password hash types from pg_authid, which is also why the reader reports missing_privilege rather than absence when it cannot')]
    private function hashTypes(array &$skips): array
    {
        /** @var list<object> $rows */
        $rows = DatabaseErrorTranslator::attempt(
            /** @return list<object> */
            fn (): array => array_values($this->session->read(static fn (Connection $db): array => $db->select(
                // The classification happens IN the server, so the hash never crosses the wire at
                // all — a `case when … like` rather than selecting `rolpassword` and inspecting it
                // here. A digest in a PHP variable is a digest a stack trace or a var-dump can carry.
                "select rolname, case when rolpassword is null then 'none'"
                ." when rolpassword like 'SCRAM-SHA-256%' then 'scram'"
                ." when rolpassword like 'md5%' then 'md5'"
                ." else 'external' end as hash_kind from pg_authid"
            ))),
            SchemaObjectType::Role,
            'pg_authid',
            $skips,
        );

        $types = [];

        foreach ($rows as $row) {
            // Both columns are computed by the query itself, so neither can be absent or empty — the
            // `case` always yields one of the four words, and `rolname` is a catalog key.
            $types[$this->text($row, 'rolname')] = PasswordHashType::from($this->text($row, 'hash_kind'));
        }

        return $types;
    }

    /**
     * The boolean columns as a {@see RoleAttribute} set.
     *
     * @return list<RoleAttribute>
     */
    private function attributes(object $row): array
    {
        $map = [
            'rolsuper' => RoleAttribute::Superuser,
            'rolcreaterole' => RoleAttribute::CreateRole,
            'rolcreatedb' => RoleAttribute::CreateDatabase,
            'rolbypassrls' => RoleAttribute::BypassRls,
            'rolcanlogin' => RoleAttribute::Login,
            'rolreplication' => RoleAttribute::Replication,
            'rolinherit' => RoleAttribute::Inherit,
        ];

        $attributes = [];

        foreach ($map as $column => $attribute) {
            if (($row->{$column} ?? false) === true) {
                $attributes[] = $attribute;
            }
        }

        return $attributes;
    }

    /** A scalar column as a string — '' when the driver answered with something else, which it does not. */
    private function text(object $row, string $key): string
    {
        return $this->nullableText($row, $key) ?? '';
    }

    /**
     * The same, keeping NULL apart from the empty string.
     *
     * The distinction carries a fact here rather than a nicety: a policy with no `USING` clause is not
     * a policy with an empty one — PostgreSQL treats the absence as "no restriction", which is the
     * same statement `USING (true)` makes, and a reader that flattened them to `''` would lose the
     * ability to say which of the two it saw.
     */
    private function nullableText(object $row, string $key): ?string
    {
        $value = $row->{$key} ?? null;

        return is_scalar($value) ? (string) $value : null;
    }

    /**
     * The aggregated membership array, which the PostgreSQL driver hands over as its literal text
     * form (`{a,b}`) rather than as a PHP array.
     *
     * @return list<string>
     */
    private function memberships(object $row, string $column = 'memberships'): array
    {
        // The driver hands a PostgreSQL array over as its literal text form (`{a,b}`), never as a PHP
        // array — measured, and the reason there is no array branch here.
        $inner = trim($this->text($row, $column), '{}');

        if ($inner === '') {
            return [];
        }

        // A role name containing a comma arrives quoted, which is exactly why this splits on the
        // quoting rather than on every comma. RoleObject::of() unquotes what is left.
        $parts = str_getcsv($inner, ',', '"', '');

        return array_values(array_filter(
            array_map(static fn (?string $part): string => trim((string) $part), $parts),
            static fn (string $part): bool => $part !== '',
        ));
    }

    #[RawSql(reason: 'reads pg_hba_file_rules -- a server view over a config file, with no other representation anywhere')]
    public function hbaRules(): HbaReading
    {
        $skips = [];

        // The ARRAY columns are joined server-side rather than parsed here. `database` and
        // `user_name` are `text[]`, and PDO hands those over as PostgreSQL array LITERALS —
        // `{all}`, `{"user one",two}` — so reading them natively would mean re-implementing an
        // array-literal parser, quoting rules included, for data the server can join in the query.
        //
        // The cost is one honest edge: a database or role name containing a comma would split. Such
        // a name is already ambiguous in pg_hba.conf itself, where these are comma-separated tokens,
        // so the file could not express it unsplit either.
        //
        // `options` is the third `text[]` column and it is deliberately NOT in this list: for `ldap`
        // and `radius` it holds a bind password or a shared secret, and no rule here needs it. See
        // {@see HbaRule} for why fetching it at all would be the mistake.
        /** @var list<object> $rows */
        $rows = DatabaseErrorTranslator::attempt(
            /** @return list<object> */
            fn (): array => array_values($this->session->read(static fn (Connection $db): array => $db->select(
                'select rule_number, file_name, line_number, type,'
                .' array_to_string(database, \',\') as databases,'
                .' array_to_string(user_name, \',\') as users,'
                .' address, netmask, auth_method,'
                .' error'
                .' from pg_hba_file_rules order by rule_number',
            ))),
            SchemaObjectType::HbaRule,
            'pg_hba_file_rules',
            $skips,
        );

        // A refusal is the NORMAL case on a managed instance, and the bar is HIGHER than the reading
        // of a mere setting: this is a view over a superuser-only function. Measured on PostgreSQL
        // 18.4 — a role holding pg_read_all_settings gets "permission denied for function
        // pg_hba_file_rules" and has_function_privilege answers f; an explicit
        // GRANT EXECUTE ON FUNCTION pg_hba_file_rules() opens it. Reporting an empty rule set on a
        // refusal would describe a server that lets nobody in — alarming, and false.
        if ($skips !== [] && $rows === []) {
            return HbaReading::refused($skips);
        }

        $rules = array_map(
            fn (object $row): HbaRule => HbaRule::of(
                // Narrowed before the cast rather than after: the driver's row is `mixed`, and a
                // rule number that arrived as something uncastable is a broken read, not a rule 0.
                is_numeric($row->rule_number ?? null) ? (int) $row->rule_number : 0,
                $this->nullableText($row, 'type'),
                $this->listed($row, 'databases'),
                $this->listed($row, 'users'),
                $this->nullableText($row, 'auth_method'),
                Readability::complete(),
                fileName: $this->nullableText($row, 'file_name'),
                lineNumber: is_numeric($row->line_number ?? null) ? (int) $row->line_number : null,
                address: $this->nullableText($row, 'address'),
                netmask: $this->nullableText($row, 'netmask'),
                error: $this->nullableText($row, 'error'),
            ),
            $rows,
        );

        return $skips === [] ? HbaReading::complete($rules) : HbaReading::partial($rules, $skips);
    }

    /**
     * The stored routines in the audited schemas, and what they run as.
     *
     * ## Why `pg_proc` and not `information_schema.ROUTINES`
     *
     * The same reason `mysql.user` is read instead of `information_schema.USER_PRIVILEGES` one engine
     * over: the SQL-standard view narrows to what the caller may see and never says that it did.
     * `pg_proc` is world-readable on PostgreSQL and returns every routine, so a restricted audit gets
     * a SHORTER answer from the standard view and an identical one from the catalog — and only one of
     * those two can be trusted to mean "there are no definer routines here".
     *
     * ## Three columns, and the one that is deliberately absent
     *
     * `prosecdef` says it runs as its owner. `proconfig` carries the routine's own `SET` clauses,
     * which is where a pinned `search_path` lives. `proowner` says whose privileges those are.
     *
     * `prosrc` — the body — is never selected. It is the likeliest place in any catalog to hold a
     * credential: an API key a migration pasted in, a connection string for a foreign server, a
     * password a trigger uses to reach another system. Same line as `pg_authid.rolpassword` and
     * `pg_hba_file_rules.options`, and for the same reason: a value in a PHP variable is a value a
     * stack trace can carry.
     *
     * ## Scoped, unlike the grant reading
     *
     * A routine is a schema OBJECT, so it belongs to the audited scope the way a table does — and an
     * unscoped read would report every extension's functions on a server with PostGIS installed. The
     * grant reading is unscoped for the opposite reason: a grant is about who may reach something,
     * and narrowing that by schema would hide the grant that matters most.
     */
    #[RawSql(reason: 'reads routine definitions, their SECURITY DEFINER flag and their search_path settings out of pg_proc')]
    public function routines(): RoutineReading
    {
        $skips = [];

        /** @var list<object> $rows */
        $rows = DatabaseErrorTranslator::attempt(
            /** @return list<object> */
            fn (): array => array_values($this->session->read(fn (Connection $db): array => $db->select(
                'select n.nspname as routine_schema, p.proname as routine_name,'
                .' pg_get_userbyid(p.proowner) as owner, p.prosecdef as definer,'
                // Joined server-side like the pg_hba array columns, and for the same reason: proconfig
                // is `text[]` and PDO hands those over as PostgreSQL array literals.
                .' array_to_string(p.proconfig, \'|\') as settings'
                .' from pg_proc p join pg_namespace n on n.oid = p.pronamespace'
                // The catalog's own routines are the server's, not the project's, and a stock install
                // has thousands. `pg_temp_*` is a session's own scratch schema.
                .' where n.nspname not in (\'pg_catalog\', \'information_schema\')'
                .' and n.nspname not like \'pg_temp%\' and n.nspname not like \'pg_toast%\''
                // Extension-owned routines belong to the extension, not to whoever installed it —
                // reporting PostGIS\'s definer functions would bury the project\'s own.
                .' and not exists ('
                .'   select 1 from pg_depend d where d.objid = p.oid'
                .'   and d.classid = \'pg_proc\'::regclass and d.deptype = \'e\''
                .' )'
                .' order by n.nspname, p.proname',
            ))),
            SchemaObjectType::Routine,
            'pg_proc',
            $skips,
        );

        // No early `refused()` arm here, unlike `hbaRules()` — and the reason is that it would be a
        // line no test on any machine can reach AND a no-op if it did. `attempt()` answers with an
        // empty list and a recorded skip when the read fails, so the fall-through below already
        // constructs `partial([], $skips)`, which is the same object `refused()` builds. `pg_hba` keeps
        // its arm because that view genuinely refuses `42501` and a real test drives it; this catalog
        // is world-readable, so the arm would be an unreachable duplicate of the line after it.

        $routines = array_map(
            fn (object $row): RoutineObject => RoutineObject::of(
                $this->text($row, 'routine_schema'),
                $this->text($row, 'routine_name'),
                $this->text($row, 'owner'),
                ($row->definer ?? false) === true,
                Readability::complete(),
                // `|` rather than `,`: a SET clause is `key=value` and a value may legitimately contain
                // a comma — `search_path=app, public` is the ordinary spelling — so splitting on one
                // would cut a single setting into two.
                settings: $this->splitOn($row, 'settings', '|'),
            ),
            $rows,
        );

        return $skips === [] ? RoutineReading::complete($routines) : RoutineReading::partial($routines, $skips);
    }

    /**
     * One joined array column, split on a chosen separator.
     *
     * @param  non-empty-string  $separator
     * @return list<string>
     */
    private function splitOn(object $row, string $key, string $separator): array
    {
        return array_values(array_filter(
            array_map(trim(...), explode($separator, $this->nullableText($row, $key) ?? '')),
            static fn (string $part): bool => $part !== '',
        ));
    }

    /**
     * One joined array column, split back into its parts.
     *
     * Empty parts are dropped rather than kept: `array_to_string` of an empty array is an empty
     * string, and exploding that yields one empty element — a phantom database name that no rule
     * should ever have to special-case.
     *
     * NULL takes the same path rather than an early return, and that is deliberate. `pg_hba_file_rules`
     * returns NULL for `database` and `user_name` on a line the server could not parse — a state this
     * suite cannot stage, because it would mean writing a broken line into the host's own pg_hba.conf
     * and reloading the cluster. A separate `if ($value === null) return []` branch would therefore be
     * a line no test on any machine can reach, which under a 100% floor is a line that has to be
     * either exercised or removed. Coalescing to the empty string reaches the identical result through
     * the path the other rows already prove: `explode(',', '')` is `['']`, and the filter drops it.
     *
     * @return list<string>
     */
    private function listed(object $row, string $key): array
    {
        return array_values(array_filter(
            array_map(trim(...), explode(',', $this->nullableText($row, $key) ?? '')),
            static fn (string $part): bool => $part !== '',
        ));
    }
}
