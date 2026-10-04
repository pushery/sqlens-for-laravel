<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Deploy;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Canonical\Identifier;
use Pushery\SQLens\Canonical\IdentifierComponent;
use Pushery\SQLens\Canonical\QuotedIdentifier;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PreflightCheck;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\DeployNotice;
use Pushery\SQLens\Deploy\PreflightContext;
use Pushery\SQLens\Deploy\PrivilegeClass;
use Pushery\SQLens\Deploy\PrivilegeRequirement;
use Pushery\SQLens\Deploy\RequiredPrivileges;
use Pushery\SQLens\Drivers\Mysql\Canonical\MysqlCanonicalization;
use Pushery\SQLens\Drivers\Mysql\Catalog\MysqlDatabasePattern;
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
 * ## Which account, and on which object
 *
 * A MySQL account is a user AND a host, and the configuration names only the user. `'deploy'@'%'` and
 * `'deploy'@'localhost'` are two accounts with separate grants, and which one `migrate` becomes
 * depends on the host it connects from, which nothing here can see. So the grants are read per
 * account and never pooled: a requirement every account meets is met, one no account meets is
 * missing, and one they disagree on is `undetermined`, naming the accounts.
 *
 * And a grant has a scope. An `ALTER` on `app.audit_log` does not let anybody alter `app.orders`, so
 * a requirement is met by a global grant, by a database-level grant whose name pattern reaches the
 * object's database, or by a table-level grant on that very table. MySQL applies ONE matching
 * database-level entry rather than their union, so only what every matching entry holds counts.
 *
 * The privilege views are filtered to what the READING connection may see, without a word: without
 * `SELECT` on the `mysql` schema it sees its own grants and nobody else's. Every account has at
 * least a `USAGE` row, so a user name the views show no account for is one this connection cannot
 * see, and the answer is `undetermined` for that reason rather than for a role nobody asked about.
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
                UndeterminedReason::MigrationRoleUnknown,
                'the configuration does not say which user runs the '
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
                UndeterminedReason::MigrationRoleMissing,
                sprintf(
                    '`%s` is named as the migration user, and `mysql.user` '
                    .'holds no account by that name. Nothing can be established about privileges it '
                    .'does not have — and a finding here would advise a `GRANT` to an account that '
                    .'does not exist, which fails in turn. Check the `username` on the migration '
                    .'connection.',
                    $role,
                ),
            );
        }

        try {
            $reading = $this->grantsOfTheName($context, $role);
            $rolesVisible = $this->holdsNoRoles($context, $role);
        } catch (Throwable $failure) {
            return CheckResult::undetermined(
                self::ID,
                UndeterminedReason::GrantsUnreadable,
                'the privilege tables could not be read, so what the migration '
                .'user may do is unknown: '.new CredentialRedactor()->redact($failure->getMessage()),
            );
        }

        if ($reading['accounts'] === []) {
            return CheckResult::undetermined(
                self::ID,
                UndeterminedReason::GrantsUnreadable,
                sprintf(
                    'the privilege views name no account called `%s`. MySQL filters them to what the '
                    .'reading connection may see, and without `SELECT` on the `mysql` schema that is '
                    .'its own grants and nobody else\'s, so nothing was established about what `%s` '
                    .'may do.',
                    $role,
                    $role,
                ),
            );
        }

        $findings = [];
        $unanswered = [];

        foreach ($requirements as $requirement) {
            if (! $requirement->isDerived()) {
                $unanswered[] = $requirement->object.': '.$requirement->undeterminedReason;

                continue;
            }

            // An index's own name is nothing MySQL grants on: `CREATE INDEX` needs INDEX on the table,
            // `ALTER TABLE … ADD INDEX` needs ALTER on it, and the table is a requirement of its own.
            // Measured: a user with ALTER on the table adds the index, and was refused here for
            // lacking CREATE on the index's name.
            if ($requirement->objectType === SchemaObjectType::Index && $requirement->class === PrivilegeClass::Create) {
                continue;
            }

            // Safe without a second `instanceof`: `isDerived()` asserts it for the analyzer above.
            $needed = $this->privilegeName($requirement->class);
            $scope = $this->objectScope($requirement, $reading['schema']);

            $reachedBy = [];
            $missingFor = [];
            $unknownFor = [];

            foreach ($reading['accounts'] as $account => $grants) {
                $reaches = $this->reaches($grants, $needed, $requirement->objectType, $scope, $reading['folds'], $reading['wildcards']);

                if ($reaches === null) {
                    $unknownFor[] = $account;
                } elseif ($reaches) {
                    $reachedBy[] = $account;
                } else {
                    $missingFor[] = $account;
                }
            }

            if ($missingFor === [] && $unknownFor === []) {
                continue;
            }

            if ($unknownFor !== []) {
                // Two different reasons, and the sentence has to name the one that applies: a name
                // that does not split at all is not an unqualified one, and the connection that read
                // it may well have a default database.
                $unanswered[] = $scope === null
                    ? sprintf(
                        '%s: which database it is in could not be established. The name does not split '
                        .'into a database and an object, which MySQL names in at most two parts, so no '
                        .'grant below the global level can be matched to it.',
                        $requirement->object,
                    )
                    : sprintf(
                        '%s: which database it is in could not be established. The name is not qualified '
                        .'and the reading connection has no default database, so no grant below the global '
                        .'level can be matched to it.',
                        $requirement->object,
                    );

                continue;
            }

            // The accounts disagree, and which one `migrate` becomes depends on the host it connects
            // from. Pooling them is what let one account's grant answer for another.
            if ($reachedBy !== []) {
                $unanswered[] = sprintf(
                    '%s: `%s` is %d accounts, and they differ on `%s`: held by %s, not by %s. Which one '
                    .'`migrate` connects as depends on the host it connects from, which this check '
                    .'cannot see.',
                    $requirement->object,
                    $role,
                    count($reading['accounts']),
                    $needed,
                    implode(', ', $reachedBy),
                    implode(', ', $missingFor),
                );

                continue;
            }

            // Not found — and on MySQL that is NOT enough to report it missing. The privilege views
            // do not expand roles, and this server cannot be asked what another user reaches through
            // one. Reporting a finding here would be a false RED on every role-based setup, which is
            // the modern one.
            if (! $rolesVisible) {
                $unanswered[] = sprintf(
                    '%s: `%s` is not among the grants `%s` holds directly on it, and whether it is '
                    .'reached through a ROLE could not be established — `mysql.role_edges` is not '
                    .'readable by this connection. Reporting it missing would be wrong for every '
                    .'setup that grants through roles.',
                    $requirement->object,
                    $needed,
                    $role,
                );

                continue;
            }

            $findings[] = $this->finding($context, $role, $requirement, $needed, $scope);
        }

        if ($unanswered !== []) {
            return CheckResult::undetermined(
                self::ID,
                UndeterminedReason::PrivilegeCheckIncomplete,
                ''.implode('; ', $unanswered),
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
            PrivilegeClass::Index => 'INDEX',
        };
    }

    /**
     * Every grant the privilege views list for this user name, by account, with the scope each one
     * applies to — and what an unqualified name and a grant's database pattern mean on this server.
     *
     * The rows are grouped by `GRANTEE`, `'user'@'host'`, because each host variant is an account of
     * its own. Global grants have neither a database nor a table, database-level grants a database
     * (as the pattern it was granted with), table-level grants both.
     *
     * @return array{accounts: array<string, list<array{privilege: string, schema: string|null, table: string|null}>>, schema: string|null, folds: bool, wildcards: bool}
     */
    #[RawSql(reason: 'reads the privileges the deploying account actually holds, and where; a preflight that guessed would pass a deploy that then fails halfway')]
    private function grantsOfTheName(PreflightContext $context, string $role): array
    {
        // A prefix comparison, not `LIKE`, and not `substring_index` either. `GRANTEE` is
        // rendered as `'user'@'host'`, so the account is everything up to and including the `'@`
        // that follows its closing quote.
        //
        // `LIKE "'{$role}'@%"` fails open: in LIKE an underscore is a single-character wildcard,
        // so `'sqlens_grant_x'` also matches `'sqlens-grant-x'` and a neighbor's `ALTER` answers for
        // this account. A deploy gate that passes a deploy which then dies halfway through
        // `migrate --force` is worse than no gate: it replaces the check somebody would otherwise
        // have made by hand. Measured on MySQL 8.4.10, exactly that pair.
        //
        // `substring_index(grantee, '@', 1)` is wrong in the other direction. It splits at the
        // first `@`, so an email-shaped account — `sqlens@mail.test`, an ordinary thing to call a
        // user — is cut in half and matches nothing at all. Measured on the same server: it returns
        // the account's privileges as an empty set, which this check would read as "holds nothing"
        // and turn into a false MISSING_PRIVILEGE finding.
        //
        // The prefix comparison has no wildcard to escape and no separator to guess at. It is bound
        // twice because the length and the value are both parameters; `char_length` counts
        // characters rather than bytes, which is what `substring` also counts.
        $prefix = "'".$role."'@";

        [$rows, $server] = $context->session->read(static fn (Connection $db): array => [
            $db->select(
                'select grantee as g, privilege_type as p, null as s, null as t from information_schema.USER_PRIVILEGES where substring(grantee, 1, char_length(?)) = ?
                 union all select grantee, privilege_type, table_schema, null from information_schema.SCHEMA_PRIVILEGES where substring(grantee, 1, char_length(?)) = ?
                 union all select grantee, privilege_type, table_schema, table_name from information_schema.TABLE_PRIVILEGES where substring(grantee, 1, char_length(?)) = ?',
                array_fill(0, 6, $prefix),
            ),
            // The database an unqualified name lands in, whether table names compare folded, and
            // whether `_` and `%` in a database-level grant are wildcards.
            $db->select('select database() as db, @@lower_case_table_names as lctn, @@partial_revokes as pr'),
        ]);

        $accounts = [];

        foreach ($rows as $row) {
            if (! is_object($row) || ! is_scalar($row->g ?? null) || ! is_scalar($row->p ?? null)) {
                continue;
            }

            $accounts[(string) $row->g][] = [
                'privilege' => strtoupper((string) $row->p),
                'schema' => is_scalar($row->s ?? null) ? (string) $row->s : null,
                'table' => is_scalar($row->t ?? null) ? (string) $row->t : null,
            ];
        }

        ksort($accounts);

        $settings = $server[0] ?? null;
        $schema = is_object($settings) && is_scalar($settings->db ?? null) ? (string) $settings->db : '';

        return [
            'accounts' => $accounts,
            'schema' => $schema === '' ? null : $schema,
            'folds' => is_object($settings) && is_numeric($settings->lctn ?? null) && (int) $settings->lctn > 0,
            'wildcards' => ! (is_object($settings) && is_numeric($settings->pr ?? null) && (int) $settings->pr === 1),
        ];
    }

    /**
     * The database and the name a requirement's object stands for, as a grant spells them.
     *
     * An unqualified name lands in the reading connection's default database, which is null when it
     * has none. Null as a whole when the object is not a name this reading can split.
     *
     * @return array{schema: string|null, name: string}|null
     */
    private function objectScope(PrivilegeRequirement $requirement, ?string $defaultSchema): ?array
    {
        $identifier = Identifier::parse($requirement->object, new MysqlCanonicalization);

        if (! $identifier instanceof Identifier) {
            return null;
        }

        // On MySQL a schema IS a database, so the object names the database itself.
        if (in_array($requirement->objectType, [SchemaObjectType::Schema, SchemaObjectType::Database], true)) {
            return ['schema' => $this->spelled($identifier->name), 'name' => $this->spelled($identifier->name)];
        }

        return [
            'schema' => $identifier->schema instanceof IdentifierComponent ? $this->spelled($identifier->schema) : $defaultSchema,
            'name' => $this->spelled($identifier->name),
        ];
    }

    /** A component as the server spells it: the canonical form without its backticks. */
    private function spelled(IdentifierComponent $component): string
    {
        $canonical = $component->canonical;

        return strlen($canonical) >= 2 && str_starts_with($canonical, '`') && str_ends_with($canonical, '`')
            ? str_replace('``', '`', substr($canonical, 1, -1))
            : $canonical;
    }

    /**
     * Whether one account's grants reach a privilege on an object, or null when that cannot be said.
     *
     * A global grant reaches everything. A database-level grant reaches the object when its name
     * pattern covers the object's database; MySQL applies one matching entry and not their union, so
     * only a privilege every matching entry holds counts. A table-level grant reaches its own table.
     * An index or any other object below a table is reached through a table the same statement names,
     * which is required on its own, so a table-level grant anywhere in its database counts. A database
     * is reached by no table-level grant at all.
     *
     * @param  list<array{privilege: string, schema: string|null, table: string|null}>  $grants
     * @param  array{schema: string|null, name: string}|null  $scope
     */
    private function reaches(array $grants, string $privilege, SchemaObjectType $type, ?array $scope, bool $folds, bool $wildcards): ?bool
    {
        foreach ($grants as $grant) {
            if ($grant['schema'] === null && $grant['privilege'] === $privilege) {
                return true;
            }
        }

        if ($scope === null || $scope['schema'] === null) {
            return null;
        }

        $same = static fn (string $a, string $b): bool => $folds ? strtolower($a) === strtolower($b) : $a === $b;
        $database = $folds ? strtolower($scope['schema']) : $scope['schema'];
        $patterns = [];

        foreach ($grants as $grant) {
            if ($grant['schema'] !== null && $grant['table'] === null) {
                $patterns[$grant['schema']][] = $grant['privilege'];
            }
        }

        $matching = null;

        foreach ($patterns as $pattern => $privileges) {
            if (MysqlDatabasePattern::covers($folds ? strtolower((string) $pattern) : (string) $pattern, $database, $wildcards)) {
                $matching = $matching === null ? $privileges : array_values(array_intersect($matching, $privileges));
            }
        }

        if ($matching !== null && in_array($privilege, $matching, true)) {
            return true;
        }

        if (in_array($type, [SchemaObjectType::Schema, SchemaObjectType::Database], true)) {
            return false;
        }

        $onATable = in_array($type, [SchemaObjectType::Table, SchemaObjectType::View], true);

        foreach ($grants as $grant) {
            if ($grant['schema'] === null || $grant['table'] === null || $grant['privilege'] !== $privilege) {
                continue;
            }

            if ($same($grant['schema'], $scope['schema']) && (! $onATable || $same($grant['table'], $scope['name']))) {
                return true;
            }
        }

        return false;
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

    /**
     * The finding for a privilege the migration user provably lacks, with the grant that supplies it.
     *
     * A database is granted on as `` `name`.* ``. Written as `ON archive`, the suggestion would name a
     * TABLE called `archive` in the default database of whoever runs it: a privilege on an object
     * nobody meant, and the deploy would fail exactly as before.
     *
     * @param  array{schema: string|null, name: string}|null  $objectScope
     */
    private function finding(PreflightContext $context, string $role, PrivilegeRequirement $requirement, string $needed, ?array $objectScope): Finding
    {
        $scope = $requirement->class === PrivilegeClass::Write ? 'INSERT, UPDATE' : $needed;
        $target = $objectScope !== null && in_array($requirement->objectType, [SchemaObjectType::Schema, SchemaObjectType::Database], true)
            ? '`'.str_replace('`', '``', $objectScope['name']).'`.*'
            : $requirement->object;

        return Finding::fail(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: sprintf(
                'The migration user `%s` holds no `%s` reaching `%s`, and holds no roles that could '
                .'carry one. `migrate --force` will not fail at the start — it will apply what it '
                .'can and stop here, leaving the schema half-migrated while the application is '
                .'already deployed against the other half. `GRANT %s ON %s TO %s@\'…\';`',
                $role,
                $needed,
                $requirement->object,
                $scope,
                $target,
                // The user as an identifier rather than a string literal: a `'` in the name would end
                // the literal, and a backslash in it reads differently under `NO_BACKSLASH_ESCAPES`.
                // A backtick-quoted part reads the same under every `sql_mode`.
                QuotedIdentifier::of('`', $role),
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
