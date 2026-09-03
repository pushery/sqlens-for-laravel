<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Deploy;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PreflightCheck;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\DeployNotice;
use Pushery\SQLens\Deploy\PreflightContext;
use Pushery\SQLens\Deploy\PrivilegeClass;
use Pushery\SQLens\Deploy\PrivilegeRequirement;
use Pushery\SQLens\Deploy\RequiredPrivileges;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SubjectContext;
use Throwable;

/**
 * Whether the MySQL role running the migrations may do what they ask for.
 *
 * Same question as the PostgreSQL sibling, and a fundamentally different answer — in the direction
 * that decides this whole class's shape.
 *
 * ## MySQL cannot answer this about somebody else, and that makes false REDS the risk
 *
 * PostgreSQL has `has_table_privilege(role, …)`, which resolves inheritance for ANY role. MySQL has
 * no equivalent. `information_schema.APPLICABLE_ROLES` lists the roles of the **current** user —
 * measured: granting a role to another user and asking about them returns zero rows — and the
 * privilege views list grants held DIRECTLY, never those reached through a role.
 *
 * So a check that reported "missing" whenever the views came up empty would be wrong for every
 * project whose migration user holds its grants through a role, which is the modern MySQL 8 setup.
 * That is the mirror image of the PostgreSQL trap: there the danger is a false GREEN (grants present,
 * ownership missing), here it is a false RED.
 *
 * The resolution is asymmetric on purpose:
 *
 * - A privilege FOUND in the views is definitive. Grants do not lie about themselves.
 * - A privilege NOT found is only a finding when this run can also establish that the user holds no
 *   roles at all — which needs `SELECT` on `mysql.role_edges`. Without that, it is `undetermined`
 *   with the reason named.
 *
 * ## No ownership here
 *
 * MySQL has no owner concept: `ALTER` is a grantable privilege like any other. So the class that
 * exists because PostgreSQL cannot grant it maps onto an ordinary `ALTER` grant, and this driver
 * never emits an ownership finding.
 *
 * @see https://dev.mysql.com/doc/refman/8.4/en/information-schema-user-privileges-table.html
 */
final readonly class GrantCheck implements PreflightCheck
{
    public const string ID = 'DEPLOY.PREFLIGHT.MISSING_PRIVILEGE';

    public function id(): string
    {
        return self::ID;
    }

    public function appliesTo(string $driver): bool
    {
        return $driver === 'mysql';
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
                'migration_role_unknown: the configuration does not say which user runs the '
                .'migrations, so whose grants to ask about is unknown. Set the `username` on the '
                .'migration connection — an empty one is not a user, and asking about it would '
                .'certify one that does not exist.',
            );
        }

        // Whether the user EXISTS, before anything is said about what they may do. Measured: a name
        // that is not an account produced a Critical finding advising `GRANT ALTER ON … TO
        // 'that_name'@'…'` — a statement which itself fails, handed to somebody inside a deploy
        // window. "Has no privileges" and "is not a user" are different problems with different
        // fixes, and only one of them is fixed by a GRANT.
        if ($this->subjectIsAbsent($context, $role)) {
            return CheckResult::undetermined(
                self::ID,
                sprintf(
                    'grant_subject_missing: `%s` is named as the migration user, and `mysql.user` '
                    .'holds no account by that name. Nothing can be established about privileges it '
                    .'does not have — and a finding here would advise a `GRANT` to an account that '
                    .'does not exist, which fails in turn. Check the `username` on the migration '
                    .'connection.',
                    $role,
                ),
            );
        }

        try {
            $held = $this->heldPrivileges($context, $role);
            $rolesVisible = $this->holdsNoRoles($context, $role);
        } catch (Throwable $failure) {
            return CheckResult::undetermined(
                self::ID,
                'grants_unreadable: the privilege tables could not be read, so what the migration '
                .'user may do is unknown: '.$failure->getMessage(),
            );
        }

        $findings = [];
        $unanswered = [];

        foreach ($requirements as $requirement) {
            if (! $requirement->isDerived()) {
                $unanswered[] = $requirement->object.': '.$requirement->undeterminedReason;

                continue;
            }

            // Safe without a second `instanceof`: `isDerived()` asserts it for the analyzer above.
            $needed = $this->privilegeName($requirement->class);

            if (in_array($needed, $held, true)) {
                continue;
            }

            // Not found — and on MySQL that is NOT enough to report it missing. The privilege views
            // do not expand roles, and this server cannot be asked what another user reaches through
            // one. Reporting a finding here would be a false RED on every role-based setup, which is
            // the modern one.
            if (! $rolesVisible) {
                $unanswered[] = sprintf(
                    '%s: `%s` is not among the grants held directly by `%s`, and whether it is '
                    .'reached through a ROLE could not be established — `mysql.role_edges` is not '
                    .'readable by this connection. Reporting it missing would be wrong for every '
                    .'setup that grants through roles.',
                    $requirement->object,
                    $needed,
                    $role,
                );

                continue;
            }

            $findings[] = $this->finding($context, $role, $requirement, $needed);
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
     * What this engine calls that class.
     *
     * A `match` over the enum rather than a lookup table, and the difference is the whole reason it
     * is a method: `match` is EXHAUSTIVE, so a class added to the enum without a MySQL name here is
     * a PHPStan error. The table it replaces needed a `?? null` and a `continue` to satisfy the
     * analyzer -- a branch nothing could enter, which would have silently skipped exactly the
     * requirement a new class was added to express.
     */
    private function privilegeName(PrivilegeClass $class): string
    {
        return match ($class) {
            PrivilegeClass::Create => 'CREATE',
            // No owner concept on MySQL: `ALTER` is grantable like any other privilege, so the class
            // that exists because PostgreSQL cannot grant it maps onto the ordinary grant here.
            PrivilegeClass::Alter, PrivilegeClass::Ownership => 'ALTER',
            PrivilegeClass::Drop => 'DROP',
            PrivilegeClass::References => 'REFERENCES',
            PrivilegeClass::Write => 'INSERT',
        };
    }

    /**
     * The privilege names this user holds DIRECTLY, at any level.
     *
     * Global, schema and table grants collapsed into one set on purpose: the question is whether the
     * user may do the thing, and a global `ALTER` answers it as well as a table-level one.
     *
     * @return list<string>
     */
    #[RawSql(reason: 'reads the privileges the deploying account actually holds; a preflight that guessed would pass a deploy that then fails halfway')]
    private function heldPrivileges(PreflightContext $context, string $role): array
    {
        $rows = $context->session->read(static fn (Connection $db): array => $db->select(
            'select privilege_type as p from information_schema.USER_PRIVILEGES where grantee like ?
             union select privilege_type from information_schema.SCHEMA_PRIVILEGES where grantee like ?
             union select privilege_type from information_schema.TABLE_PRIVILEGES where grantee like ?',
            array_fill(0, 3, "'".$role."'@%"),
        ));

        $held = [];

        foreach ($rows as $row) {
            if (is_object($row) && is_scalar($row->p ?? null)) {
                $held[] = strtoupper((string) $row->p);
            }
        }

        return array_values(array_unique($held));
    }

    /**
     * Whether the account is provably absent.
     *
     * True ONLY when `mysql.user` is readable AND holds no row for this name. Unreadable answers
     * false — the same direction as {@see self::holdsNoRoles()}, and for the same reason: on a
     * managed instance that view is closed, and turning "cannot tell" into "does not exist" would
     * refuse every deploy it cannot see.
     */
    #[RawSql(reason: 'asks whether the account exists at all, so a missing subject is reported as missing rather than as unprivileged')]
    private function subjectIsAbsent(PreflightContext $context, string $role): bool
    {
        try {
            $rows = $context->session->read(static fn (Connection $db): array => $db->select(
                'select count(*) as n from mysql.user where user = ?',
                [$role],
            ));
        } catch (Throwable) {
            return false;
        }

        $row = $rows[0] ?? null;
        $count = is_object($row) ? $row->n ?? null : null;

        return is_numeric($count) && (int) $count === 0;
    }

    /**
     * Whether this run can establish that the user holds NO roles.
     *
     * True only when `mysql.role_edges` is readable AND empty for this user. False means "cannot
     * tell", which is why the caller treats it as a reason to withhold a finding rather than as a
     * reason to emit one — the two states must not collapse into each other.
     */
    #[RawSql(reason: 'reads granted roles from the catalog; role membership is not a model relation')]
    private function holdsNoRoles(PreflightContext $context, string $role): bool
    {
        try {
            $rows = $context->session->read(static fn (Connection $db): array => $db->select(
                'select count(*) as n from mysql.role_edges where to_user = ?',
                [$role],
            ));
        } catch (Throwable) {
            // Not readable is the ordinary case for an unprivileged reader, and on a managed
            // instance it is the only case. Not an error — a limit, and one the caller names.
            return false;
        }

        $row = $rows[0] ?? null;
        $count = is_object($row) ? $row->n ?? null : null;

        // Only a real zero counts. Anything the driver hands back that is not a number leaves this
        // "cannot tell", which is the safe direction here — the caller withholds a finding rather
        // than emitting one.
        return is_numeric($count) && (int) $count === 0;
    }

    private function finding(PreflightContext $context, string $role, PrivilegeRequirement $requirement, string $needed): Finding
    {
        $scope = $requirement->class === PrivilegeClass::Write ? 'INSERT, UPDATE' : $needed;

        return Finding::fail(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: sprintf(
                'The migration user `%s` holds no `%s` reaching `%s`, and holds no roles that could '
                .'carry one. `migrate --force` will not fail at the start — it will apply what it '
                .'can and stop here, leaving the schema half-migrated while the application is '
                .'already deployed against the other half. `GRANT %s ON %s TO \'%s\'@\'…\';`',
                $role,
                $needed,
                $requirement->object,
                $scope,
                $requirement->object,
                $role,
            ),
            location: Location::inCatalog($context->driver, $context->connection, $requirement->object, $requirement->objectType),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::ID),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            severity: Severity::Critical,
        )->withDowntimeClass(DowntimeClass::Blocking);
    }
}
