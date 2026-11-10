<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Deploy;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Canonical\QuotedIdentifier;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PreflightCheck;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\Checks\PreflightStateUnreadable;
use Pushery\SQLens\Deploy\DeployNotice;
use Pushery\SQLens\Deploy\PreflightContext;
use Pushery\SQLens\Deploy\PrivilegeClass;
use Pushery\SQLens\Deploy\PrivilegeRequirement;
use Pushery\SQLens\Deploy\RequiredPrivileges;
use Pushery\SQLens\Drivers\Pgsql\Catalog\ApplicationSearchPath;
use Pushery\SQLens\Findings\CredentialRedactor;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;
use Throwable;

/**
 * Whether the role running the migrations may actually do what they ask for.
 *
 * The failure this catches is the one that wastes a deploy window: `migrate --force` runs, applies
 * four of nine migrations, and stops on a permission the role never had. The schema is now
 * half-migrated, the application is deployed against the other half, and the fix is a rollback under
 * time pressure.
 *
 * ## Why PostgreSQL answers this and we do not
 *
 * `has_table_privilege(role, object, privilege)` follows role INHERITANCE on its own — a role that
 * holds the grant through two levels of membership answers true, and reimplementing that traversal
 * would be a second opinion about the server's own rules.
 *
 * Ownership needs a different question, and that is the whole reason
 * {@see PrivilegeClass::Ownership} exists: `ALTER TABLE` cannot be granted on PostgreSQL. It
 * requires ownership, so the question is `pg_has_role(role, relowner, 'USAGE')` and no `GRANT`
 * answers it. A check that asked for a privilege here would advise something nobody can do.
 *
 * ## An object that does not exist yet is not a missing privilege
 *
 * A migration that creates a table names an object the catalog has never seen, and asking
 * `has_table_privilege` about it raises. So existence is established first, and an absent object is
 * judged at the SCHEMA instead — which is the right question anyway: creating a table needs `CREATE`
 * on the schema, not anything on a table that is not there.
 */
final readonly class GrantCheck implements PreflightCheck
{
    public const string ID = 'DEPLOY.PREFLIGHT.MISSING_PRIVILEGE';

    /**
     * Missing OWNERSHIP, which is a different finding from a missing grant.
     *
     * Its own id because the two send a reader to different actions and because the confusion
     * between them is the expensive one: a role can hold every grant on a table and still be unable
     * to `ALTER` it. A check that reported both under one id would let somebody read "missing
     * privilege", run the `GRANT` it names, and watch the next deploy fail identically.
     */
    public const string OWNERSHIP_ID = 'DEPLOY.CONTEXT.GRANT.OWNERSHIP_MISSING';

    public function id(): string
    {
        return self::ID;
    }

    public function appliesTo(string $driver): bool
    {
        return $driver === 'pgsql';
    }

    public function run(PreflightContext $context): CheckResult
    {
        if ($context->pending->isEmpty()) {
            return CheckResult::pass(self::ID);
        }

        $requirements = RequiredPrivileges::forPending($context->pending, new PgsqlTargetlessPrivileges);

        if ($requirements === []) {
            return CheckResult::pass(self::ID);
        }

        $role = $context->migrationRole;

        if ($role === null) {
            return CheckResult::undetermined(
                self::ID,
                UndeterminedReason::MigrationRoleUnknown,
                'the configuration does not say which role runs the '
                .'migrations, so whose privileges to ask about is unknown. Set the `username` on the '
                .'migration connection — an empty one is not a role, and asking about it would '
                .'certify a role that does not exist.',
            );
        }

        // Asked once, before any privilege question, because a role that does not exist makes every
        // one of them raise with the same message — and that message reads as "the grants could not
        // be read", which sends somebody to study ACLs over what is almost always a typo in the
        // connection's `username`.
        //
        // Not a failure. A role that does not exist has no privileges, so reporting every
        // requirement as missing would be technically true and useless: the deploy is not short of
        // a grant, it is pointed at nobody.
        if (! $this->roleExists($context, $role)) {
            return CheckResult::undetermined(
                self::ID,
                UndeterminedReason::MigrationRoleMissing,
                'the role the `username` of the migration connection names does not exist on this '
                    .'server. Nothing was established about any privilege — check that `username` '
                    .'before reading grants.',
            );
        }

        $findings = [];
        $unanswered = [];

        foreach ($requirements as $requirement) {
            if (! $requirement->isDerived()) {
                // The derivation could not say what this object needs, so this check cannot say
                // whether the role has it. Carried through rather than dropped: an object nobody
                // classified must not end up looking like an object nobody had to be allowed to
                // touch.
                $unanswered[] = $requirement->object.': '.$requirement->undeterminedReason;

                continue;
            }

            try {
                $answer = $this->isAllowed($context, $role, $requirement);
            } catch (Throwable $failure) {
                $unanswered[] = $requirement->object.': the server refused the privilege question ('
                    .new CredentialRedactor()->redact($failure->getMessage()).')';

                continue;
            }

            if ($answer['allowed'] === false) {
                $findings[] = $this->finding($context, $role, $requirement, $requirement->class, $answer);
            }
        }

        // A privilege that is missing for certain decides the run, whatever else stayed unanswered:
        // the migration stops at that statement either way, and an undetermined answer can be
        // waived where a missing privilege must not be. What stayed unanswered is reported once
        // the missing privilege is granted.
        if ($findings !== []) {
            return CheckResult::fail(self::ID, $findings);
        }

        return $unanswered === []
            ? CheckResult::pass(self::ID)
            : CheckResult::undetermined(self::ID, UndeterminedReason::PrivilegeCheckIncomplete, implode('; ', $unanswered));
    }

    /**
     * Whether the role owns the named schema — `pg_namespace.nspowner`, with inheritance.
     *
     * `pg_has_role(…, 'USAGE')` and not `'MEMBER'`, which is the same distinction the object case
     * makes and for the same measured reason: `MEMBER` answers whether the role could `SET ROLE` to
     * the owner, `USAGE` whether it holds the owner's privileges right now. A role that inherits
     * ownership answers true to the second and false to the first, so asking for `MEMBER` here would
     * fail a deploy that PostgreSQL itself would have allowed.
     *
     * ## Why this is not the object query with a different catalog
     *
     * It is the same SHAPE and a different question, and keeping them apart is what makes the
     * report actionable. `CREATE` **inside** a schema is a GRANT — `has_schema_privilege(…,
     * 'CREATE')`, which the arm above asks. `ALTER` or `DROP` **of** the schema is OWNERSHIP, which
     * no grant produces. Reported the wrong way round, a reader is sent to hand out a privilege that
     * would change nothing.
     *
     * ## What it does not cover, said out loud
     *
     * `ALTER SCHEMA` does not reach here, because the grammar does not classify it — see
     * {@see StatementKind::DropSchema} for why that stayed out. The destructive sibling is the one
     * that is captured, which is the right half to have if only one is: a `DROP SCHEMA` the role
     * does not own fails a deploy and would have been irreversible had it succeeded.
     */
    #[RawSql(reason: 'reads pg_namespace.nspowner through pg_has_role; a schema owner has no other representation, and reimplementing role inheritance would be a second opinion about the server own rules')]
    private function ownsSchema(PreflightContext $context, string $role, string $schema): bool
    {
        $row = $context->session->read(static fn (Connection $db): array => $db->select(
            'select pg_catalog.pg_has_role(?, n.nspowner, \'USAGE\') as allowed from pg_namespace n where n.nspname = ?',
            [$role, $schema],
        ))[0] ?? null;

        // No row means the schema is not there. That is not a refusal and must not read as one:
        // a migration set may create the schema before dropping it, and a run that has not created
        // it yet names one the catalog cannot see. Raising leaves the caller to report it unanswered,
        // which is the same treatment the object case gives a vanished relation.
        if (! is_object($row)) {
            throw new PreflightStateUnreadable(sprintf(
                'the schema `%s` is not in this database, so whether the role owns it cannot be '
                .'answered — which is not the same as the role being refused.',
                $schema,
            ));
        }

        return ($row->allowed ?? false) === true;
    }

    /**
     * Whether the role owns the named routine, or is a member of the role that does.
     *
     * Read from `pg_proc.proowner` through `pg_has_role`, as the owner of a relation is. A name with
     * its argument types, `public.touch_updated_at()`, picks one routine of an overloaded name; a
     * name without them is resolved over the application's path and must name exactly one.
     */
    #[RawSql(reason: 'reads pg_proc.proowner through pg_has_role; the owner of a routine has no other representation, and reimplementing role inheritance would be a second opinion about the server own rules')]
    private function ownsRoutine(PreflightContext $context, string $role, string $routine): bool
    {
        $withArguments = str_contains($routine, '(');

        $row = $context->session->read(static fn (Connection $db): array => $db->select(
            'select pg_catalog.pg_has_role(?, p.proowner, \'USAGE\') as allowed from pg_catalog.pg_proc p where p.oid = '
                .($withArguments ? ApplicationSearchPath::regprocedure() : ApplicationSearchPath::regproc()),
            [$role, ...($withArguments ? [$routine] : ApplicationSearchPath::regclassBindings($routine))],
        ))[0] ?? null;

        // No row means no single routine of that name was found: it is not there, or the name is
        // shared by several and carries no argument types. Neither is a refusal, so it raises and
        // the caller reports it unanswered, as it does for a schema that is not there.
        if (! is_object($row)) {
            throw new PreflightStateUnreadable(sprintf(
                'no single routine `%s` is in this database, so whether the role owns it cannot be '
                .'answered. A name that several routines share is written with its argument types, '
                .'`name(integer)`, and qualified with its schema.',
                $routine,
            ));
        }

        return ($row->allowed ?? false) === true;
    }

    /**
     * Whether no routine of the name is there at all, which is how a first deploy finds one that an
     * earlier pending migration creates. A name with its argument types is absent when
     * `to_regprocedure()` finds nothing; a name without them when no routine carries it where
     * {@see ApplicationSearchPath::routineExists()} looks. A name several routines share is there.
     */
    #[RawSql(reason: 'reads pg_proc through to_regprocedure() and parse_ident(); whether a routine is there at all has no other representation')]
    private function routineIsAbsent(PreflightContext $context, string $routine): bool
    {
        $row = $context->session->read(static fn (Connection $db): array => $db->select(
            str_contains($routine, '(')
                ? 'select '.ApplicationSearchPath::regprocedure().' is null as absent'
                : 'select not '.ApplicationSearchPath::routineExists().' as absent',
            [$routine],
        ))[0] ?? null;

        return is_object($row) && ($row->absent ?? false) === true;
    }

    /**
     * Whether the role may create the named extension: it is installed already, so the statement
     * needs nothing, the role is a superuser, or the extension is trusted and the role holds CREATE
     * on the database. A name quoted in the migration is asked about without its quotes.
     */
    #[RawSql(reason: 'reads pg_extension, pg_roles and pg_available_extension_versions and asks has_database_privilege(); whether an extension is trusted and who may create it have no other representation')]
    private function mayCreateExtension(PreflightContext $context, string $role, string $extension): bool
    {
        $name = preg_match('/^"(.*)"$/s', $extension, $quoted) === 1 ? str_replace('""', '"', $quoted[1]) : $extension;

        $row = $context->session->read(static fn (Connection $db): array => $db->select(
            'select exists (select 1 from pg_catalog.pg_extension where extname = ?)'
            .' or coalesce((select rolsuper from pg_catalog.pg_roles where rolname = ?), false)'
            .' or (coalesce((select pg_catalog.bool_or(trusted) from pg_catalog.pg_available_extension_versions where name = ?), false)'
            .' and pg_catalog.has_database_privilege(?, pg_catalog.current_database(), \'CREATE\')) as allowed',
            [$name, $role, $name, $role],
        ))[0] ?? null;

        return is_object($row) && ($row->allowed ?? false) === true;
    }

    /**
     * Whether this server knows the role at all.
     *
     * `pg_roles` rather than `pg_authid`: the former is readable by any connected role, the latter
     * needs superuser. A preflight that could only answer this question as a superuser would answer
     * it for nobody.
     */
    #[RawSql(reason: 'reads pg_roles to establish that the migration role exists at all; a role name has no other representation, and every privilege function raises identically without it')]
    private function roleExists(PreflightContext $context, string $role): bool
    {
        return $context->session->read(static fn (Connection $db): array => $db->select(
            'select 1 from pg_roles where rolname = ?',
            [$role],
        )) !== [];
    }

    /**
     * Whether the role may do this, asked of the server rather than reasoned about here, and where
     * the question went.
     *
     * A suggestion has to name what was asked: `CREATE` is granted on the schema a name lands in,
     * never on the name, and an object that does not exist yet is judged at that schema whatever
     * its class. `schema` is the schema the server resolved for that question, and null when the
     * application's search path names none that exists.
     *
     * @return array{allowed: bool, atSchema: bool, schema: string|null}
     */
    #[RawSql(reason: 'asks pg_catalog.has_table_privilege() and friends -- server functions that answer the exact question a preflight has, without the reader having to reimplement ACL resolution')]
    private function isAllowed(PreflightContext $context, string $role, PrivilegeRequirement $requirement): array
    {
        $object = $requirement->object;
        // The schema a CREATE of this name lands in: the one it names, or for a bare name the first
        // schema on the application's path, which is where the server puts it.
        $schema = str_contains($object, '.') ? explode('.', $object, 2)[0] : null;

        // A SCHEMA is asked about in the schema catalog, and everything below this line would ask
        // the wrong one. `to_regclass` resolves RELATIONS, so it answers null for a schema that
        // exists — which would route a `DROP SCHEMA` into the CREATE arm and certify a permission
        // nobody checked. `pg_class` has no row for it either, so the ownership arm would come back
        // empty and be reported as a race.
        //
        // Ownership is the right question here for the same reason it is for `ALTER TABLE`:
        // `DROP SCHEMA` cannot be granted on PostgreSQL. It needs membership in the owning role.
        if ($requirement->objectType === SchemaObjectType::Schema) {
            return ['allowed' => $this->ownsSchema($context, $role, $object), 'atSchema' => false, 'schema' => null];
        }

        // A routine is no relation either, so `to_regclass` never finds one: its owner is read from
        // `pg_proc`. Changing a routine needs its ownership, which is what a DO block that alters a
        // function declares; creating one is a CREATE and is asked at its schema below.
        //
        // A routine that is not there at all is one an earlier migration of the same run creates,
        // as on a first deploy, where every migration is pending. The role that creates it owns it
        // afterwards, so it is asked at its schema, as an absent relation is. A name that several
        // routines share is there, and ownsRoutine() reports it unanswered.
        $routineToCreate = $requirement->objectType === SchemaObjectType::Routine
            && $requirement->class !== PrivilegeClass::Create
            && $this->routineIsAbsent($context, $object);

        if ($requirement->objectType === SchemaObjectType::Routine && $requirement->class !== PrivilegeClass::Create && ! $routineToCreate) {
            return ['allowed' => $this->ownsRoutine($context, $role, $object), 'atSchema' => false, 'schema' => null];
        }

        // An extension is no relation and lands in no schema a privilege could be asked of, so it is
        // asked of the database, the way PostgreSQL decides it.
        if ($requirement->objectType === SchemaObjectType::Extension) {
            return ['allowed' => $this->mayCreateExtension($context, $role, $object), 'atSchema' => false, 'schema' => null];
        }

        // Existence first. `has_table_privilege` RAISES for an object the catalog does not have, and
        // a migration that creates a table names exactly such an object — so the absent case is
        // judged at the schema, which is the right question for a CREATE anyway.
        // A routine about to be created is known to be absent, and `to_regclass` would parse a name with
        // argument types as a relation's.
        $exists = $routineToCreate ? null : $context->session->read(static fn (Connection $db): array => $db->select(
            'select '.ApplicationSearchPath::regclass().' is not null as present',
            ApplicationSearchPath::regclassBindings($object),
        ))[0] ?? null;

        $present = is_object($exists) && ($exists->present ?? false) === true;

        $atSchema = ! $present || $requirement->class === PrivilegeClass::Create;

        [$sql, $bindings] = match (true) {
            $atSchema => [
                'select pg_catalog.has_schema_privilege(?, coalesce(?::name, '.ApplicationSearchPath::currentSchema().'), \'CREATE\') as allowed,'
                .' coalesce(?::name, '.ApplicationSearchPath::currentSchema().')::text as schema',
                [$role, $schema, $schema],
            ],
            $requirement->class === PrivilegeClass::Ownership, $requirement->class === PrivilegeClass::Index => [
                // Not a privilege. `ALTER TABLE` requires OWNERSHIP, and no GRANT produces it — so
                // the question is membership in the owning role, which is what PostgreSQL itself
                // checks before it allows the statement.
                'select pg_catalog.pg_has_role(?, c.relowner, \'USAGE\') as allowed'
                .' from pg_class c where c.oid = '.ApplicationSearchPath::regclass(),
                [$role, ...ApplicationSearchPath::regclassBindings($object)],
            ],
            // A grant rather than ownership: the table's owner holds TRIGGER, and another role can be
            // given it, so `has_table_privilege` answers both.
            $requirement->class === PrivilegeClass::Trigger => [
                'select pg_catalog.has_table_privilege(?, '.ApplicationSearchPath::regclass().', \'TRIGGER\') as allowed',
                [$role, ...ApplicationSearchPath::regclassBindings($object)],
            ],
            $requirement->class === PrivilegeClass::References => [
                'select pg_catalog.has_table_privilege(?, '.ApplicationSearchPath::regclass().', \'REFERENCES\') as allowed',
                [$role, ...ApplicationSearchPath::regclassBindings($object)],
            ],
            $requirement->class === PrivilegeClass::Write => [
                'select pg_catalog.has_table_privilege(?, '.ApplicationSearchPath::regclass().', \'INSERT\')'
                .' and pg_catalog.has_table_privilege(?, '.ApplicationSearchPath::regclass().', \'UPDATE\') as allowed',
                [$role, ...ApplicationSearchPath::regclassBindings($object), $role, ...ApplicationSearchPath::regclassBindings($object)],
            ],
            // DROP is not grantable on PostgreSQL either, but ownership of the TABLE is not the only
            // thing that permits it — the SCHEMA owner may drop a table inside their schema whoever
            // created it. `DROP TABLE`'s own description says so: "only the table owner, the schema
            // owner, and superuser can drop a table."
            //
            // The schema owner counts as well as the table owner. Asking only about `relowner`
            // would refuse a migration role that owns the schema while another role created the
            // tables, with `OWNERSHIP_MISSING` at Critical, and send it to `ALTER TABLE … OWNER TO`
            // — an ownership transfer it does not need. Measured on 18.0: with the table owned by one
            // role and the schema by another, `relowner` alone answers `false`, this answers `true`,
            // and the server accepts the DROP.
            //
            // The ALTER arm above stays with the table owner, and the same measurement settles
            // that: `ALTER TABLE … ADD COLUMN` by the schema owner is refused with "must be owner of
            // table". The two classes are kept apart so a project is told which of them it is short
            // of, and they ask different questions.
            default => [
                'select pg_catalog.pg_has_role(?, c.relowner, \'USAGE\')'
                .' or pg_catalog.pg_has_role(?, n.nspowner, \'USAGE\') as allowed'
                .' from pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace'
                .' where c.oid = '.ApplicationSearchPath::regclass(),
                [$role, $role, ...ApplicationSearchPath::regclassBindings($object)],
            ],
        };

        $row = $context->session->read(
            static fn (Connection $db): array => $db->select($sql, $bindings),
        )[0] ?? null;

        // No row means the object vanished between the two reads, which is a race rather than a
        // refusal. Answering `true` would certify a permission nobody checked, so it raises and the
        // caller reports it as unanswered.
        if (! is_object($row)) {
            // Named, and unconditionally so — which is a claim about the arms of the match above
            // rather than a shortcut. Only the two OWNERSHIP questions join `pg_class`, and only a
            // join can come back with nothing; `has_schema_privilege` and `has_table_privilege`
            // always answer with exactly one row, or they raise and never reach here. So an empty
            // answer at this point means one thing: the OWNER could not be established, because the
            // object went away between the existence probe and this one, or the connecting role
            // cannot read the catalog row that names it.
            //
            // A conditional here would carry a branch nothing can enter — untestable, unable to go
            // red, and load-bearing for the sentence a reader acts on.
            throw new PreflightStateUnreadable(
                UndeterminedReason::OwnershipUnreadable->value.': the catalog named no owner for '
                    .$object.', so nothing was established',
            );
        }

        $resolved = $row->schema ?? null;

        return [
            'allowed' => ($row->allowed ?? false) === true,
            'atSchema' => $atSchema,
            'schema' => is_string($resolved) ? $resolved : null,
        ];
    }

    /**
     * @param  PrivilegeClass  $class  passed in rather than re-read off the requirement: the caller's
     *                                 `isDerived()` guard is what makes it non-null, and an
     *                                 `instanceof` repeated here would carry an arm nothing can
     *                                 enter — untestable, unable to go red, and load-bearing for
     *                                 exactly the message a reader acts on
     * @param  array{allowed: bool, atSchema: bool, schema: string|null}  $answer  where the question went
     */
    private function finding(PreflightContext $context, string $role, PrivilegeRequirement $requirement, PrivilegeClass $class, array $answer): Finding
    {
        // Ownership and a missing grant are different findings, and telling them apart is the
        // expensive distinction: a role can hold every grant on a table and still not be able to
        // ALTER it. One id for both would let somebody read "missing privilege", run the GRANT it
        // names, and watch the next deploy fail identically.
        // A routine asked about at its schema is one the run creates, and what it needs there is CREATE,
        // which a grant gives: the creator owns it afterwards.
        $routineToCreate = $requirement->objectType === SchemaObjectType::Routine && $answer['atSchema'];
        $ownership = ! $routineToCreate && in_array($class, [PrivilegeClass::Ownership, PrivilegeClass::Drop, PrivilegeClass::Index], true);

        // The role as a statement names it. It comes from the configuration, and unquoted a name
        // like `app-migrator` does not parse while `AppMigrator` folds to `appmigrator`, another role
        // or none. Quoted, the suggestion can only reach the role the check asked about.
        $grantee = QuotedIdentifier::of('"', $role);

        // The two ownership cases need different sentences. `DROP TABLE` accepts the schema owner
        // as well as the table owner — measured on 18.0 — so telling a schema owner they "must own
        // the table" would be advice for a transfer they do not need.
        // `ALTER TABLE` really does need the table, and the same measurement shows it: the schema
        // owner is refused with "must be owner of table".
        $needs = match (true) {
            $requirement->objectType === SchemaObjectType::Extension => sprintf(
                'may not create the extension `%s`: PostgreSQL lets a role create a trusted extension '
                .'with CREATE on the database, `GRANT CREATE ON DATABASE <database> TO %s`, and asks a '
                .'superuser for any other one, so have one install it before the deploy',
                $requirement->object,
                $grantee,
            ),
            // A routine is handed over by naming it as one, as a schema is. `ALTER ROUTINE` covers a
            // function and a procedure alike.
            $requirement->objectType === SchemaObjectType::Routine && ! $routineToCreate => sprintf(
                'must own the routine `%s`, and ownership cannot be granted — no `GRANT` produces it. '
                .'Either `ALTER ROUTINE %s OWNER TO %s`, or make %s a member of the role that owns it',
                $requirement->object,
                $requirement->object,
                $grantee,
                $role,
            ),
            // A schema is handed over by naming it as one: `ALTER TABLE` on a schema name finds no
            // relation, measured on 18 as `relation "app_ns" does not exist`.
            $requirement->objectType === SchemaObjectType::Schema => sprintf(
                'must own the schema `%s`, and ownership cannot be granted — no `GRANT` produces it. '
                .'Either `ALTER SCHEMA %s OWNER TO %s`, or make %s a member of the role that owns it',
                $requirement->object,
                $requirement->object,
                $grantee,
                $role,
            ),
            // `CREATE INDEX` needs the TABLE's owner. Measured on 18: a role with every grant on the
            // table and CREATE in its schema is refused with `must be owner of table`.
            $class === PrivilegeClass::Index => sprintf(
                'must own `%s` to build an index on it — `CREATE INDEX` requires the table\'s owner, '
                .'and no `GRANT` produces it. Either `ALTER TABLE %s OWNER TO %s`, or make %s a member '
                .'of the role that owns it',
                $requirement->object,
                $requirement->object,
                $grantee,
                $role,
            ),
            $class === PrivilegeClass::Drop => sprintf(
                'must own `%s` or the schema it lives in — `DROP TABLE` accepts either, and no `GRANT` '
                .'produces it. Either `ALTER TABLE %s OWNER TO %s`, make %s the owner of the schema, or '
                .'make %s a member of a role that is one of the two',
                $requirement->object,
                $requirement->object,
                $grantee,
                $role,
                $role,
            ),
            $ownership => sprintf(
                'must OWN `%s`, and ownership cannot be granted — `ALTER TABLE` requires the TABLE '
                .'itself, which owning the schema does not give, and no `GRANT` produces it. Either '
                .'`ALTER TABLE %s OWNER TO %s`, or make %s a member of the role that owns it',
                $requirement->object,
                $requirement->object,
                $grantee,
                $role,
            ),
            // Asked at the schema, so granted there. `GRANT CREATE ON <table>` names a relation,
            // and for a table the migration is about to create there is none.
            $answer['atSchema'] && $answer['schema'] !== null => sprintf(
                'needs CREATE on the schema `%s` that `%s` is created in — `GRANT CREATE ON SCHEMA %s TO %s`',
                $answer['schema'],
                $requirement->object,
                QuotedIdentifier::of('"', $answer['schema']),
                $grantee,
            ),
            // The server answered the CREATE question about no schema at all, because none on the
            // application's search path exists. A grant cannot fix that, so none is suggested.
            $answer['atSchema'] => sprintf(
                'needs CREATE on the schema `%s` is created in, and the search path of the connection '
                .'names no schema that exists — set its `search_path`, or qualify the name',
                $requirement->object,
            ),
            // The two privileges the check asked about. PostgreSQL has no privilege called WRITE.
            $class === PrivilegeClass::Write => sprintf(
                'needs INSERT and UPDATE on `%s` — `GRANT INSERT, UPDATE ON %s TO %s`',
                $requirement->object,
                $requirement->object,
                $grantee,
            ),
            default => sprintf(
                'needs %s on `%s` — `GRANT %s ON %s TO %s`',
                strtoupper($class->value),
                $requirement->object,
                strtoupper($class->value),
                $requirement->object,
                $grantee,
            ),
        };

        return Finding::fail(
            ruleId: $ownership ? self::OWNERSHIP_ID : self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: sprintf(
                'The migration role `%s` %s. `migrate --force` will not fail at the start — it will '
                .'apply what it can and stop here, leaving the schema half-migrated while the '
                .'application is already deployed against the other half. That is the failure this '
                .'check exists to move from the deploy window to now.',
                $role,
                $needs,
            ),
            location: Location::inCatalog($context->driver, $context->connection, $requirement->object, $requirement->objectType),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for($ownership ? self::OWNERSHIP_ID : self::ID),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            severity: Severity::Critical,
        )->withDowntimeClass(
            // `blocking`: the deploy stops halfway. Not `online` — the application is already live
            // against a schema that is only partly there.
            DowntimeClass::Blocking,
        );
    }
}
