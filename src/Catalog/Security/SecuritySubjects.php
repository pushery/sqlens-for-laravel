<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Security;

use Pushery\SQLens\Catalog\Objects\GrantObject;
use Pushery\SQLens\Catalog\Objects\GrantReading;
use Pushery\SQLens\Catalog\Objects\HbaReading;
use Pushery\SQLens\Catalog\Objects\HbaRule;
use Pushery\SQLens\Catalog\Objects\Privilege;
use Pushery\SQLens\Catalog\Objects\RlsReading;
use Pushery\SQLens\Catalog\Objects\RlsState;
use Pushery\SQLens\Catalog\Objects\RoleAttribute;
use Pushery\SQLens\Catalog\Objects\RoleObject;
use Pushery\SQLens\Catalog\Objects\RoleReading;
use Pushery\SQLens\Catalog\Objects\RoutineObject;
use Pushery\SQLens\Catalog\Objects\RoutineReading;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * The security readings, as subjects the ordinary rule machinery can judge.
 *
 * This is the seam, and it is deliberately the same one the settings reading uses: a security rule is
 * then an ordinary catalog rule, judged by the same runner, filtered by the same level and category
 * gates, reported by the same reporters, suppressed by the same baseline. Nothing about a rule that
 * reads a role has to be new — which is the difference between a suite and a second suite.
 *
 * ## What travels, and why these fields specifically
 *
 * A rule must never re-derive what the reader already established, because two derivations drift and
 * only one of them is tested. Two fields matter more than the rest:
 *
 * - **`system`** — the accounts the ENGINE ships (`mysql.*`, the `pg_` predefined roles). Without it
 *   every role rule opens with findings nobody caused on a fresh server.
 * - **`origin`** — who made a grant. Every PostgreSQL database carries `CONNECT`/`TEMPORARY` to PUBLIC
 *   and `EXECUTE` to PUBLIC on a hundred-odd system functions out of the box; a rule that reported
 *   those would be switched off in its first week.
 *
 * ## Readability travels too, and it is not decoration
 *
 * A partial object says which FIELDS it could not read. A rule that judges one of them must report
 * `undetermined` rather than a verdict — an account reported as unprivileged because nobody could read
 * its privileges is the silent green this whole package refuses.
 */
final readonly class SecuritySubjects
{
    /**
     * Every account and every grant in the two readings, as subjects.
     *
     * Sorted by identity within each kind, so a run over an unchanged server produces the same order:
     * the readers already sort, and this keeps that property through the merge.
     *
     * @return list<SchemaObject>
     */
    public static function fromReadings(
        RoleReading $roles,
        GrantReading $grants,
        RlsReading $rls,
        HbaReading $hba,
        RoutineReading $routines,
        SubjectContext $context,
        ConnectionSeparation $separation = new ConnectionSeparation,
    ): array {
        // Resolved ONCE, from the role reading, and stamped onto every table subject. An RLS rule that
        // re-derived it per table would ask the same question of the same data as many times as the
        // project has tenant tables — and the four of them would each have their own version of the
        // answer, which is how two rules end up disagreeing about one server.
        $bypass = self::bypassingRoles($roles);
        $connected = self::connectedRole($roles);

        // The same reasoning, for the routine side: who may CREATE in which schema is one question
        // about the grant reading, and a routine rule deriving it per routine would ask it once per
        // definer routine over the same rows.
        $creators = self::schemaCreators($grants);

        return [
            ...array_map(static fn (RoleObject $role): SchemaObject => self::role($role, $rls, $hba, $context, $separation), $roles->roles),
            ...array_map(static fn (GrantObject $grant): SchemaObject => self::grant($grant, $context, $separation, $connected), $grants->grants),
            ...array_map(static fn (RlsState $state): SchemaObject => self::rlsState($state, $bypass, $connected, $context), $rls->states),
            ...array_map(static fn (HbaRule $rule): SchemaObject => self::hbaRule($rule, $context), $hba->rules),
            ...array_map(static fn (RoutineObject $routine): SchemaObject => self::routine($routine, $creators, $context), $routines->routines),
        ];
    }

    /**
     * Whether a grantee names the same account as this role.
     *
     * Two spellings have to meet here. PostgreSQL grants to a bare role name; MySQL canonicalizes a
     * grantee as `'name'@'host'`, and the role carries the two halves separately. Comparing the bare
     * names alone would make `'app'@'10.0.0.%'` and `'app'@'%'` the same account, which they are
     * not — one of them may be the audit connection and the other the application's.
     */
    private static function isSameAccount(string $grantee, RoleObject $role): bool
    {
        if ($grantee === $role->name) {
            return true;
        }

        return $role->host !== null && $grantee === sprintf("'%s'@'%s'", $role->name, $role->host);
    }

    /** The account the audit connected as, or null when the reading did not establish one. */
    private static function connectedRole(RoleReading $roles): ?RoleObject
    {
        foreach ($roles->roles as $role) {
            if ($role->connectionRole) {
                return $role;
            }
        }

        return null;
    }

    /**
     * Whether the audited connection IS the table's owner, or can become it.
     *
     * Membership counts, and it is not a refinement: a role that is a member of the owner reaches
     * every object the owner holds by simply being a member — PostgreSQL applies an owner's exemption
     * to any role that has the owner's rights through membership, so a comparison on the name alone
     * would answer no for the arrangement most deploys actually have (`app` a member of `app_owner`).
     */
    private static function ownedByConnection(RlsState $state, ?RoleObject $connected): bool
    {
        if ($state->owner === '' || ! $connected instanceof RoleObject) {
            return false;
        }

        return $state->owner === $connected->name || in_array($state->owner, $connected->reachableRoles, true);
    }

    /**
     * The accounts row-level security does not apply to, as a sorted, comma-joined string.
     *
     * Held OR reachable: PostgreSQL does not inherit attributes through membership, but an account one
     * `SET ROLE` from `BYPASSRLS` reads every row the moment it takes that step, and an RLS finding
     * that ignored the second shape would tell a project its tables are covered when they are not.
     * Superusers are included without carrying the attribute — a superuser bypasses RLS by definition,
     * and leaving it out here would make the most exposed account the one nothing mentions.
     */
    private static function bypassingRoles(RoleReading $roles): string
    {
        $names = [];

        foreach ($roles->roles as $role) {
            $bypasses = $role->has(RoleAttribute::BypassRls)
                || $role->has(RoleAttribute::Superuser)
                || $role->canReach(RoleAttribute::BypassRls)
                || $role->canReach(RoleAttribute::Superuser);

            if ($bypasses && ! $role->system) {
                $names[] = $role->identity();
            }
        }

        sort($names);

        return implode(',', $names);
    }

    /**
     * One table's row-level security state.
     *
     * A `Table` subject rather than a type of its own, because that is what it is about and what a
     * report groups by — and it carries `rls_scoped` so an RLS rule can tell it apart from the table
     * subjects the ordinary catalog reader produces for every table in the schema. Without that marker
     * the four RLS rules would judge every table in the database, which is exactly the guessing the
     * reader refuses to do one layer down.
     */
    private static function rlsState(RlsState $state, string $bypassingRoles, ?RoleObject $connected, SubjectContext $context): SchemaObject
    {
        return new SchemaObject(
            SchemaObjectType::Table,
            $state->table,
            $state->table,
            [
                // The marker, and the reason it is not merely implied by the other keys: a table with
                // RLS off carries `rls_enabled => false`, and so would every unrelated table if one of
                // them ever grew the key by accident.
                'rls_scoped' => true,
                'rls_enabled' => $state->enabled,
                // `FORCE` is separate because `ENABLE` does not apply to the table's OWNER, and an
                // application connecting as the role that owns its tables — the ordinary Laravel setup
                // — bypasses every policy without any attribute showing up anywhere.
                'rls_forced' => $state->forced,
                'rls_policy_count' => count($state->policies),
                'rls_locked_out' => $state->isLockedOut(),
                'rls_always_true' => $state->hasAlwaysTruePolicy(),
                // The offending policies BY NAME, comma-joined — the attribute bag is scalar-only by
                // contract, and a rule that reported a count would send somebody through the whole
                // policy list to find the one that is wrong.
                'rls_always_true_policies' => implode(',', $state->alwaysTruePolicyNames()),
                'rls_always_true_checks' => implode(',', $state->alwaysTrueCheckPolicyNames()),
                // What makes RLS beside the point for these accounts however well the policies are
                // written. A finding that told somebody to switch RLS on without saying this would be
                // promising a protection that one account still walks straight through.
                'rls_bypassing_roles' => $bypassingRoles,
                // The owner, and whether it is the account this run connected as. Decided here, once,
                // from the two readings — a rule resolving membership per table would be a second
                // implementation of the role closure, and the two would disagree the first time one
                // of them was fixed.
                'rls_owner' => $state->owner,
                'rls_owner_is_connection' => self::ownedByConnection($state, $connected),
                'readability' => $state->readability->state->value,
                'withheld_fields' => implode(',', $state->readability->withheldFields),
            ],
            $context,
        );
    }

    /**
     * One `pg_hba.conf` line as a subject the security rules can judge.
     *
     * ## No `hba_supported` marker here, unlike `rls_scoped` one method up
     *
     * The RLS states have to carry one because they are `Table` subjects, indistinguishable from the
     * table subjects the ordinary catalog reader produces for every table in the schema. An HBA rule
     * has {@see SchemaObjectType::HbaRule} to itself, so its existence IS the marker — a MySQL run
     * produces none of these subjects at all, which is how the five rules stay silent there without
     * any of them knowing what engine it is. What that arrangement cannot express — "supported, but
     * nobody could read it" — is stamped on the ROLE subject instead, because it has to be said on a
     * run that produced no HBA subjects whatsoever.
     *
     * ## What is deliberately NOT here
     *
     * `options`. HBA options carry LDAP bind parameters and RADIUS secrets — and the reading does not
     * hold them either: the PostgreSQL reader never selects the column. So this is the second half of
     * one decision rather than a redaction, and the difference matters — a redaction can be undone by
     * somebody who wants the field; there is nothing here to undo.
     */
    private static function hbaRule(HbaRule $rule, SubjectContext $context): SchemaObject
    {
        return new SchemaObject(
            SchemaObjectType::HbaRule,
            $rule->location(),
            // The file is the parent a report groups by: one bad pg_hba.conf produces several
            // findings, and a reader wants them together.
            $rule->fileName,
            [
                'rule_number' => $rule->ruleNumber,
                'type' => $rule->type,
                'auth_method' => $rule->authMethod,
                // Decided once, here, from PostgreSQL's own naming — every network type starts with
                // `host`. Five rules deriving it would be five copies of one fact.
                'is_network' => $rule->isNetwork(),
                'address' => $rule->address,
                'netmask' => $rule->netmask,
                // The canonical answer to "does this line accept the whole internet", resolved on the
                // object because `all`, `0.0.0.0/0` and `0.0.0.0 0.0.0.0` are three spellings of it.
                'open_cidr' => $rule->isOpenToTheWorld(),
                'databases' => implode(',', $rule->databases),
                'users' => implode(',', $rule->users),
                // A line the SERVER could not parse. It authenticates nobody, so the four rules that
                // judge content report `undetermined` on it rather than a verdict about fields the
                // server left empty.
                'is_broken' => $rule->isBroken(),
                'parse_error' => $rule->error,
                'readability' => $rule->readability->state->value,
            ],
            $context,
        );
    }

    /**
     * Schema name => the grantees who may CREATE in it, from the grant reading alone.
     *
     * `PUBLIC` arrives as an empty grantee and is kept as `PUBLIC`, because it is the answer that
     * matters most here: a schema anyone may create in is the classic search-path substitution.
     *
     * @return array<string, list<string>>
     */
    private static function schemaCreators(GrantReading $grants): array
    {
        $creators = [];

        foreach ($grants->grants as $grant) {
            if ($grant->objectType !== SchemaObjectType::Schema) {
                continue;
            }

            if (! in_array(Privilege::Create, $grant->privileges, true)) {
                continue;
            }

            $creators[$grant->objectName][] = $grant->grantee === '' ? GrantObject::PUBLIC_GRANTEE : $grant->grantee;
        }

        return $creators;
    }

    /**
     * The schemas a routine's own `search_path` names, in order, as the server stored them.
     *
     * Read from the reader's settings list rather than re-parsed from a catalog string: the reader
     * already split `proconfig`, and a second parser is a second thing to be wrong.
     *
     * @return list<string>
     */
    private static function pathSchemas(RoutineObject $routine): array
    {
        foreach ($routine->settings as $setting) {
            if (! str_starts_with(strtolower($setting), 'search_path=')) {
                continue;
            }

            $value = substr($setting, strlen('search_path='));

            return array_values(array_filter(array_map(
                static fn (string $part): string => trim($part, " \t\"'"),
                explode(',', $value),
            ), static fn (string $part): bool => $part !== ''));
        }

        return [];
    }

    /**
     * One stored routine as a subject, described by what it runs AS.
     *
     * ## Two flags, and why the second is not implied by the first
     *
     * `definer` says the routine runs with its OWNER's privileges. `pins_search_path` says it fixes
     * the namespace its unqualified names resolve in. Neither is a finding alone: a definer routine
     * that pins its path is the ordinary, recommended construction, and a routine that pins nothing
     * while running as its caller is simply a routine.
     *
     * It is the COMBINATION that is exploitable, and carrying both separately is what lets two rules
     * of different severity say two different true things about it rather than one rule guessing.
     *
     * ## What is deliberately NOT here
     *
     * The body. `prosrc` is the likeliest place in a catalog to hold a credential, and the readers do
     * not select it — so this is the second half of one decision rather than a redaction. The `SET`
     * clauses ARE here, because `search_path=app, public` is configuration rather than code; a routine
     * that put a secret in a SET clause would have put it in `pg_proc` for every reader on the server.
     *
     * @param  array<string, list<string>>  $creators  schema name => who may CREATE in it
     */
    private static function routine(RoutineObject $routine, array $creators, SubjectContext $context): SchemaObject
    {
        $path = self::pathSchemas($routine);

        // The measurement done once here rather than per rule: which schemas
        // in this routine's own path may somebody OTHER than its owner create in? That is a fact
        // about the catalog, not an opinion about which values count as safe — which is what makes
        // it answerable at all. A pinned path is not automatically a safe one.
        $writable = array_values(array_filter(
            $path,
            static fn (string $schema): bool => array_any(
                $creators[$schema] ?? [],
                static fn (string $grantee): bool => $grantee !== $routine->owner,
            ),
        ));

        // `pg_temp` is the caller's OWN schema. Anywhere but last in the path it is the same
        // substitution gap, with a schema the attacker does not even have to be granted.
        $temp = array_search('pg_temp', $path, true);

        return new SchemaObject(
            SchemaObjectType::Routine,
            $routine->identity(),
            // The schema is the parent a report groups by — a definer routine rarely arrives alone.
            $routine->schema === '' ? null : $routine->schema,
            [
                'owner' => $routine->owner,
                'definer' => $routine->definer,
                // Decided once, here, from the reader's own settings list. Two rules asking it would
                // be two implementations of one question, and they would disagree the first time one
                // of them learned about a new way to spell it.
                'pins_search_path' => $routine->pinsSearchPath(),
                // Whether the ENGINE has the concept at all. Without it an empty settings list on
                // MySQL — which has no per-routine search path — would read as "definer and unpinned",
                // and the critical rule would fire on every definer routine on every MySQL server.
                'search_path_configurable' => $routine->pathConfigurable,
                'settings' => implode(',', $routine->settings),
                // The two ways a PINNED path can still be unsafe, both as facts rather than verdicts:
                // the schemas in it somebody else may create in, and whether `pg_temp` sits anywhere
                // but last. Empty and false are the ordinary answers, and a rule that reads them says
                // nothing when they are.
                'path_schemas_others_may_create_in' => implode(',', $writable),
                'pg_temp_not_last' => $temp !== false && $temp !== count($path) - 1,
                'readability' => $routine->readability->state->value,
            ],
            $context,
        );
    }

    private static function role(RoleObject $role, RlsReading $rls, HbaReading $hba, SubjectContext $context, ConnectionSeparation $separation): SchemaObject
    {
        return new SchemaObject(
            SchemaObjectType::Role,
            $role->identity(),
            null,
            [
                'name' => $role->name,
                // Null on PostgreSQL, where a role has no host at all — the absence is the answer.
                'host' => $role->host,
                // The attribute set as a sorted, comma-joined string: the subject's attribute bag is
                // scalar-only by contract (a mixed array would break Larastan max at the first rule),
                // and a rule asks with `str_contains(…, 'superuser')` on a value that cannot vary in
                // order. `has()` on the object stays the readable form for anything that holds one.
                'attributes' => self::joined($role->attributes),
                // What the account can BECOME through membership, kept apart from what it HAS — the
                // engines do not inherit attributes, and a rule that conflated them would report a
                // plain application role as a superuser.
                'reachable_attributes' => self::joined($role->reachableAttributes),
                'memberships' => implode(',', $role->memberships),
                'reachable_roles' => implode(',', $role->reachableRoles),
                // `reached=path;reached=path`, because the attribute bag is scalar-only by contract.
                // The paths matter to a rule that has to tell somebody WHICH grant to revoke, and a
                // finding that named only the endpoint would leave them guessing on a chain.
                'reachable_paths' => implode(';', array_map(
                    static fn (string $reached, string $path): string => $reached.'='.$path,
                    array_keys($role->reachablePaths),
                    array_values($role->reachablePaths),
                )),
                'hash_type' => $role->hashType->value,
                'valid_until' => $role->validUntil,
                'privileged' => $role->isPrivileged(),
                'wildcard_host' => $role->hasWildcardHost(),
                // The empty user name, as a decided fact rather than a string a rule has to test.
                // It is the one attribute whose SUBJECT cannot name itself: an anonymous account's
                // identity renders as `''@'host'`, so a finding about it has to say what that means.
                'anonymous' => $role->isAnonymous(),
                'system' => $role->system,
                // The project's own answer to "which connection serves requests" — carried on the
                // subject rather than read from config inside a rule, because a rule that reached for
                // the container would be a rule no unit test could put in a state.
                'runtime_connection' => $separation->runtime,
                'migration_connection' => $separation->migration,
                // WHO each of those is, beside WHAT it is called. A project may file two connection
                // names that authenticate as one user against one host and one database, and the
                // separation then exists in config/database.php and nowhere else. Null means the
                // configuration did not say — which the rule reports as undetermined rather than
                // folding into "separate".
                'runtime_identity' => $separation->runtimeIdentity,
                'migration_identity' => $separation->migrationIdentity,
                // Whether this RUN is looking at the runtime connection — as a word rather than a
                // bool, because a bool has only two of the three answers. `undetermined` is the one
                // that matters: a rule judging the CONNECTING role must not assume it is the runtime
                // role, or it names the migration role and tells somebody to revoke what their
                // deploy needs.
                'audited_is_runtime' => match ($separation->auditedIsRuntime()) {
                    true => 'yes',
                    false => 'no',
                    null => 'undetermined',
                },
                // The one the role rules judge: a rule reporting every privileged account on a server
                // would report the one every server ships.
                'connection_role' => $role->connectionRole,
                'usable' => $role->usable,
                // The DDL right for which no grant exists. Null travels as null, not as zero: a
                // reading that could not ask must not answer "owns nothing", which is exactly the
                // shape a clean server has.
                'owned_tables' => $role->ownedTables,
                // The RLS reading's two states, carried on the ONE subject every run has. A rule that
                // has to say "nothing was checked" needs something to attach that to, and a run whose
                // project named no tables has no table subject by construction — which is precisely the
                // state that must not pass silently.
                'rls_supported' => $rls->supported,
                'rls_configured' => $rls->configured,
                // The third state, and the reason `rls_configured` alone was not enough: a project
                // that set the mode to `off` answered the question, and answering it must not produce
                // the same line as never having been asked.
                'rls_declined' => $rls->declined,
                // …and WHY, when the answer was "the application separates them". A sentence rather
                // than a fourth boolean: the rule quotes it, so the report carries the project's own
                // words instead of a category nobody can act on.
                'rls_application_separation' => $rls->applicationSeparation,
                // The HBA reading's two states, on the same subject and for the same reason. A refused
                // reading produces NO hba subjects, so a rule that had to say "this server's
                // authentication rules could not be read" would have nothing to attach it to — and an
                // empty rule list reads exactly like a server with no dangerous lines, which is the
                // silent green in its purest form. `hba_supported` is false only on an engine that has
                // no such file at all; `hba_readable` is what separates "there is nothing to report"
                // from "nobody was allowed to look".
                'hba_supported' => $hba->supported,
                'hba_readable' => $hba->isComplete(),
                'hba_rule_count' => count($hba->rules),
                'readability' => $role->readability->state->value,
                // Which fields the reading could not get, so a rule judging one of them can say
                // `undetermined` with the reason instead of a verdict it has no basis for.
                'withheld_fields' => implode(',', $role->readability->withheldFields),
            ],
            $context,
        );
    }

    private static function grant(GrantObject $grant, SubjectContext $context, ConnectionSeparation $separation, ?RoleObject $connected): SchemaObject
    {
        return new SchemaObject(
            SchemaObjectType::Grant,
            $grant->objectType->value.':'.$grant->objectName.':'.$grant->grantee,
            // The object the grant is ON — the parent a report groups by, and the thing a reader goes
            // and looks at.
            $grant->objectName,
            [
                'grantee' => $grant->grantee,
                'grantor' => $grant->grantor,
                'target_type' => $grant->objectType->value,
                'target' => $grant->objectName,
                'privileges' => self::joined($grant->privileges),
                'other_privileges' => implode(',', $grant->otherPrivileges),
                'grantable' => $grant->grantable,
                // Whether the grant carries EVERY privilege the engine permits on this kind of
                // object. Stamped by the reader rather than derived here, because answering it needs
                // the engine's own vocabulary and this layer is engine-neutral by contract.
                'all_privileges' => $grant->coversEveryPrivilege,
                'to_public' => $grant->isToPublic(),
                'structural' => $grant->isStructural(),
                'origin' => $grant->origin->value,
                // The one question every grant rule starts from: did somebody here decide this, or is
                // it what the engine ships?
                'judgeable' => $grant->isJudgeable(),
                // Whether this grant is one the RUNTIME role holds, and whether that role is also the
                // one migrations deploy with. Both decided here, once, from the reading and the config
                // — a rule deriving it per grant would be three derivations of one fact.
                'runtime_grantee' => $separation->isRuntimeGrantee($grant->grantee, $connected->reachableRoles ?? []),
                'runtime_is_migration' => $separation->runtimeIsMigration(),
                // Whether this grant belongs to the account SQLens itself connected as. Derived once
                // here from the role reading, because a rule asking it would have to walk the roles
                // again per grant — and because getting it wrong has a specific cost: a tool that
                // reports the very privileges its own documented setup asks for is a tool nobody
                // trusts twice. MySQL spells a grantee `'name'@'host'`, so the comparison is against
                // the same spelling rather than against the bare name.
                'connection_grantee' => $connected instanceof RoleObject
                    && self::isSameAccount($grant->grantee, $connected),
                'readability' => $grant->readability->state->value,
            ],
            $context,
        );
    }

    /**
     * @param  list<RoleAttribute|Privilege>  $values
     */
    private static function joined(array $values): string
    {
        return implode(',', array_map(static fn (RoleAttribute|Privilege $value): string => $value->value, $values));
    }
}
