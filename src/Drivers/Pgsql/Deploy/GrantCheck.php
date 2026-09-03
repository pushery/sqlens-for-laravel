<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Deploy;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
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
     * between them is the expensive one: a role can hold EVERY grant on a table and still be unable
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

        $requirements = RequiredPrivileges::forPending($context->pending);

        if ($requirements === []) {
            return CheckResult::pass(self::ID);
        }

        $role = $context->migrationRole;

        if ($role === null) {
            return CheckResult::undetermined(
                self::ID,
                'migration_role_unknown: the configuration does not say which role runs the '
                .'migrations, so whose privileges to ask about is unknown. Set the `username` on the '
                .'migration connection — an empty one is not a role, and asking about it would '
                .'certify a role that does not exist.',
            );
        }

        // Asked ONCE, before any privilege question, because a role that does not exist makes every
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
                UndeterminedReason::MigrationRoleMissing->value.': the migration connection names '
                    .'the role `'.$role.'`, and this server has no such role. Nothing was '
                    .'established about any privilege — check the username before reading grants.',
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
                $allowed = $this->isAllowed($context, $role, $requirement);
            } catch (Throwable $failure) {
                $unanswered[] = $requirement->object.': the server refused the privilege question ('
                    .$failure->getMessage().')';

                continue;
            }

            if ($allowed === false) {
                $findings[] = $this->finding($context, $role, $requirement, $requirement->class);
            }
        }

        if ($unanswered !== []) {
            return CheckResult::undetermined(
                self::ID,
                'privilege_check_incomplete: '.implode('; ', $unanswered),
                $findings,
            );
        }

        return $findings === []
            ? CheckResult::pass(self::ID)
            : CheckResult::fail(self::ID, $findings);
    }

    /**
     * Whether the role owns the named schema — `pg_namespace.nspowner`, with inheritance.
     *
     * `pg_has_role(…, 'USAGE')` and NOT `'MEMBER'`, which is the same distinction the object case
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
     * ## What it does NOT cover, said out loud
     *
     * `ALTER SCHEMA` does not reach here, because the grammar does not classify it — see
     * {@see StatementKind::DropSchema} for why that stayed out. The destructive sibling is the one
     * that is captured, which is the right half to have if only one is: a `DROP SCHEMA` the role
     * does not own fails a deploy AND would have been irreversible had it succeeded.
     */
    #[RawSql(reason: 'reads pg_namespace.nspowner through pg_has_role; a schema owner has no other representation, and reimplementing role inheritance would be a second opinion about the server own rules')]
    private function ownsSchema(PreflightContext $context, string $role, string $schema): bool
    {
        $row = $context->session->read(static fn (Connection $db): array => $db->select(
            'select pg_has_role(?, n.nspowner, \'USAGE\') as allowed from pg_namespace n where n.nspname = ?',
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

    /** Whether the role may do this, asked of the server rather than reasoned about here. */
    #[RawSql(reason: 'asks has_table_privilege() and friends -- server functions that answer the exact question a preflight has, without the reader having to reimplement ACL resolution')]
    private function isAllowed(PreflightContext $context, string $role, PrivilegeRequirement $requirement): bool
    {
        $object = $requirement->object;
        $schema = str_contains($object, '.') ? explode('.', $object, 2)[0] : 'public';

        // A SCHEMA is asked about in the schema catalog, and everything below this line would ask
        // the wrong one. `to_regclass` resolves RELATIONS, so it answers null for a schema that
        // exists — which would route a `DROP SCHEMA` into the CREATE arm and certify a permission
        // nobody checked. `pg_class` has no row for it either, so the ownership arm would come back
        // empty and be reported as a race.
        //
        // Ownership is the right question here for the same reason it is for `ALTER TABLE`:
        // `DROP SCHEMA` cannot be granted on PostgreSQL. It needs membership in the owning role.
        if ($requirement->objectType === SchemaObjectType::Schema) {
            return $this->ownsSchema($context, $role, $object);
        }

        // Existence first. `has_table_privilege` RAISES for an object the catalog does not have, and
        // a migration that creates a table names exactly such an object — so the absent case is
        // judged at the schema, which is the right question for a CREATE anyway.
        $exists = $context->session->read(static fn (Connection $db): array => $db->select(
            'select to_regclass(?) is not null as present',
            [$object],
        ))[0] ?? null;

        $present = is_object($exists) && ($exists->present ?? false) === true;

        [$sql, $bindings] = match (true) {
            ! $present, $requirement->class === PrivilegeClass::Create => [
                'select has_schema_privilege(?, ?, \'CREATE\') as allowed',
                [$role, $schema],
            ],
            $requirement->class === PrivilegeClass::Ownership => [
                // Not a privilege. `ALTER TABLE` requires OWNERSHIP, and no GRANT produces it — so
                // the question is membership in the owning role, which is what PostgreSQL itself
                // checks before it allows the statement.
                'select pg_has_role(?, c.relowner, \'USAGE\') as allowed'
                .' from pg_class c where c.oid = to_regclass(?)',
                [$role, $object],
            ],
            $requirement->class === PrivilegeClass::References => [
                'select has_table_privilege(?, ?, \'REFERENCES\') as allowed',
                [$role, $object],
            ],
            $requirement->class === PrivilegeClass::Write => [
                'select has_table_privilege(?, ?, \'INSERT\') and has_table_privilege(?, ?, \'UPDATE\') as allowed',
                [$role, $object, $role, $object],
            ],
            // Drop, like Alter, is not grantable on PostgreSQL: it needs ownership. Kept as its own
            // arm rather than folded into the one above, because the two classes exist so a project
            // can be told which of them it is short of.
            default => [
                'select pg_has_role(?, c.relowner, \'USAGE\') as allowed'
                .' from pg_class c where c.oid = to_regclass(?)',
                [$role, $object],
            ],
        };

        $row = $context->session->read(
            static fn (Connection $db): array => $db->select($sql, $bindings),
        )[0] ?? null;

        // No row means the object vanished between the two reads, which is a race rather than a
        // refusal. Answering `true` would certify a permission nobody checked, so it raises and the
        // caller reports it as unanswered.
        if (! is_object($row)) {
            // NAMED, and unconditionally so — which is a claim about the four arms above rather
            // than a shortcut. Only the two OWNERSHIP questions join `pg_class`, and only a join can
            // come back with nothing; `has_schema_privilege` and `has_table_privilege` always answer
            // with exactly one row, or they raise and never reach here. So an empty answer at this
            // point means one thing: the OWNER could not be established, because the object went away
            // between the existence probe and this one, or the connecting role cannot read the
            // catalog row that names it.
            //
            // A conditional here would carry a branch nothing can enter — untestable, unable to go
            // red, and load-bearing for the sentence a reader acts on.
            throw new PreflightStateUnreadable(
                UndeterminedReason::OwnershipUnreadable->value.': the catalog named no owner for '
                    .$object.', so nothing was established',
            );
        }

        return ($row->allowed ?? false) === true;
    }

    /**
     * @param  PrivilegeClass  $class  passed in rather than re-read off the requirement: the caller's
     *                                 `isDerived()` guard is what makes it non-null, and an
     *                                 `instanceof` repeated here would carry an arm nothing can
     *                                 enter — untestable, unable to go red, and load-bearing for
     *                                 exactly the message a reader acts on
     */
    private function finding(PreflightContext $context, string $role, PrivilegeRequirement $requirement, PrivilegeClass $class): Finding
    {
        // Ownership and a missing grant are different findings, and telling them apart is the
        // expensive distinction: a role can hold EVERY grant on a table and still not be able to
        // ALTER it. One id for both would let somebody read "missing privilege", run the GRANT it
        // names, and watch the next deploy fail identically.
        $ownership = $class === PrivilegeClass::Ownership || $class === PrivilegeClass::Drop;

        $needs = $ownership
            ? sprintf(
                'must OWN `%s`, and ownership cannot be granted — `ALTER TABLE` and `DROP` require '
                .'it, and no `GRANT` produces it. Either `ALTER TABLE %s OWNER TO %s`, or make %s a '
                .'member of the role that owns it',
                $requirement->object,
                $requirement->object,
                $role,
                $role,
            )
            : sprintf(
                'needs %s on `%s` — `GRANT %s ON %s TO %s`',
                strtoupper($class->value),
                $requirement->object,
                strtoupper($class->value),
                $requirement->object,
                $role,
            );

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
