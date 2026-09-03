<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The application's runtime role may create objects — which is what turns an injected statement into
 * a schema change.
 *
 * This is the single most effective thing a project can do about SQL injection at the database layer,
 * and it is not a code change: run the application on a role that cannot perform DDL, and deploy
 * migrations on a different one. An injection that reaches a runtime role with `CREATE` can add a
 * table, a function, a trigger — a foothold that outlives the request and the deploy. The same
 * injection against a role holding only DML reads and writes rows, which is bad and is a different
 * incident.
 *
 * ## What it checks, and the honesty limit
 *
 * It reads PRIVILEGES, not behavior. A clean result here does not mean the application is safe from
 * injection; it means one specific consequence of one is off the table. The finding says so, because a
 * security rule that let a reader believe otherwise would be worse than none.
 *
 * ## Why an unconfigured project gets `undetermined` rather than a pass
 *
 * The rule needs to know WHICH connection is the runtime one. Without `security.runtime_connection`
 * there is nothing to judge — and guessing would be worse than silence: on a project with one
 * connection the guess is right by accident, and on a project with five it names the wrong role and
 * sends somebody to revoke a privilege their deploy depends on.
 *
 * A project that genuinely runs everything on one connection says so by leaving both keys null, and
 * gets the finding that state deserves: the runtime role IS the migration role, so it holds DDL by
 * necessity, and the fix is a second connection rather than a revoke.
 */
final class RuntimeDdlRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes
{
    /**
     * Grants AND the connecting role.
     *
     * Grants because that is where a privilege somebody granted lives — and the grant reading is
     * refusable on a managed database, which makes "no subject" an ordinary state here rather than a
     * check that ran.
     *
     * The ROLE because ownership is a DDL right for which **no grant exists**: an owner may `ALTER`
     * and `DROP` its tables outright, the privilege sits in `pg_class.relowner`, and no grant row
     * mentions it. Reading only grants there produces silence, and silence is what a role holding
     * nothing produces too. Same rule and same id, because it is the same question — a runtime
     * connection that can change the schema — asked of the other place the answer hides.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Grant, SchemaObjectType::Role];
    }

    public function id(): string
    {
        return 'SEC.PRIV.RUNTIME_DDL';
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    /**
     * Medium, and the reason is the catalog's own axis rather than a feeling about this rule.
     *
     * The `SEC.PRIV.*` family does not split on "reads privileges" versus "reads behavior" — every
     * member reads privileges. It splits on whether the privilege ESCAPES the database:
     * `ROLE_SUPERUSER`, `ROLE_BYPASSRLS`, `GRANT_ALL`, `GRANT_FILE`, `GRANT_SERVER_ADMIN` and
     * `GRANT_OPTION_STRUCTURAL` are high; `ROLE_CREATEROLE`, `GRANT_OPTION`, `GRANT_PROCESS`,
     * `GRANT_PUBLIC` and `CONNECTIONS_UNSEPARATED` are medium.
     *
     * DDL on the application's OWN database is broad and bounded, which puts it with
     * `ROLE_CREATEROLE` rather than with `ROLE_SUPERUSER`. The comparison that settles it is the one
     * next door: `GRANT_OPTION` is medium and `GRANT_OPTION_STRUCTURAL` is high, over the same
     * privilege, differing only in reach.
     *
     * The escalated case is not swallowed by this. A runtime role that ALSO holds `SUPERUSER` or
     * `ALL PRIVILEGES` is reported at high by the rules that own those facts — so the severe
     * arrangement is reported severely, by the rule whose subject it is, instead of this one
     * inflating to cover a case it does not read.
     */
    public function severity(): Severity
    {
        return Severity::Medium;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type === SchemaObjectType::Role) {
            return $this->judgeOwnership($object);
        }

        if ($object->type !== SchemaObjectType::Grant) {
            return [];
        }

        // Only what the runtime role itself holds. A grant to another role is another role's business,
        // and one to PUBLIC is already reported by SEC.PRIV.GRANT_PUBLIC — with a better message for it.
        if ($object->getBool('runtime_grantee') !== true) {
            return [];
        }

        // The `structural` stamp rather than a second derivation. This rule used to ask its own
        // question — `CREATE`, `TRUNCATE` or `ALTER SYSTEM` in the canonical list — and on MySQL that
        // is nearly the empty set: `TRUNCATE` and `ALTER SYSTEM` do not exist there, and `ALTER`,
        // `DROP`, `INDEX`, `CREATE ROUTINE` and `EVENT` all arrive under their own engine names. A
        // runtime connection that could rebuild every table and install a stored routine was reported
        // by nothing, and the rule looked like a rule with nothing to say.
        //
        // One definition, in the object, supplied per engine by the reader that knows its
        // vocabulary. Two definitions of one concept is how the second one goes stale unnoticed.
        if ($object->getBool('structural') !== true) {
            return [];
        }

        return [RuleVerdict::flag($this->message($object))];
    }

    /**
     * The half no grant row carries: the runtime role OWNS the application's tables.
     *
     * ## Why it speaks only when the run is looking at the runtime connection
     *
     * This branch judges the CONNECTING role, and that is a different risk from the grant branch
     * above. A grant branch pointed at the wrong connection finds no matching row and stays quiet —
     * a false negative nobody acts on. This one would report the MIGRATION role as the runtime one
     * and tell somebody to revoke exactly the privilege their deploy needs.
     *
     * So it requires the run to have established that it is looking at the runtime connection.
     * `undetermined` there is deliberately SILENT rather than a second undetermined finding: the
     * project not having said which connection serves requests is already reported once, by
     * {@see UnseparatedConnectionsRule}, and saying it twice would make a reader chase two entries
     * to one missing config key.
     *
     * @return list<RuleVerdict>
     */
    private function judgeOwnership(SchemaObject $object): array
    {
        $owned = $object->getInt('owned_tables');

        if ($object->getBool('connection_role') !== true
            || $object->getString('audited_is_runtime') !== 'yes'
            || $owned === null
            || $owned < 1) {
            return [];
        }

        return [RuleVerdict::flag(sprintf(
            'the runtime role %s OWNS %d application %s, and an owner may ALTER and DROP them without '
            .'any grant saying so — which is why no privilege list shows this. A SQL injection that '
            .'reaches this connection can therefore change the schema rather than only the rows. '
            .'Ownership follows whoever ran the migration that created the table, so this is the '
            .'ordinary result of deploying on the connection that serves requests: create a role for '
            .'migrations, let it own the tables, and give the runtime role only DML on them.',
            $object->qualifiedName,
            $owned,
            $owned === 1 ? 'table' : 'tables',
        ))];
    }

    private function message(SchemaObject $object): string
    {
        $shared = $object->getBool('runtime_is_migration') === true;

        return sprintf(
            'the runtime role %s holds %s on the %s %s, so a SQL injection that reaches this connection '
            .'can change the schema rather than only the rows: it can leave a table, a function or a '
            .'trigger behind, which outlives the request. %s This rule reads PRIVILEGES, not behavior — '
            .'a clean result here does not mean the application cannot be injected, only that one '
            .'consequence of it is off the table.',
            $object->getString('grantee') ?? '?',
            $this->privilegeList($object),
            $object->getString('target_type') ?? 'object',
            $object->getString('target') ?? '?',
            $shared ? $this->sharedConnectionAdvice() : $this->separateConnectionAdvice($object),
        );
    }

    /**
     * What to do when the same connection deploys and serves — and it is NOT a revoke.
     *
     * The distinction decides whether the advice is usable at all: on a one-connection project the DDL
     * rights are there because the DEPLOY needs them, and revoking them breaks the next migration.
     */
    private function sharedConnectionAdvice(): string
    {
        return 'This project runs migrations on the same connection, so the role holds DDL by necessity '
            .'— the fix is a second connection for migrations, not a REVOKE that would break the next deploy.';
    }

    /** What to do when the connections are already separate: the runtime role simply has too much. */
    private function separateConnectionAdvice(SchemaObject $object): string
    {
        return sprintf(
            'REVOKE %s ON %s FROM %s once the migration connection is the one that deploys.',
            $this->privilegeList($object),
            $object->getString('target') ?? '?',
            $object->getString('grantee') ?? '?',
        );
    }

    /**
     * What the grant carries, in names a reader can put in a `REVOKE`.
     *
     * The canonical list alone will not do here, and the reason is the same one that made this rule
     * silent on MySQL: nearly every MySQL privilege that changes a schema maps to the unmapped case,
     * so a message built from it would tell somebody their role holds "other, other, other". The
     * engine's own names are carried on the subject precisely so they can be said out loud.
     *
     * Unmapped names first and canonical ones after, both sorted, so two runs over an unchanged
     * server produce the same sentence.
     */
    private function privilegeList(SchemaObject $object): string
    {
        $engine = array_values(array_filter(explode(',', $object->getString('other_privileges') ?? '')));

        $canonical = array_values(array_filter(
            explode(',', $object->getString('privileges') ?? ''),
            // `other` is the placeholder for exactly the names already listed above it.
            static fn (string $name): bool => $name !== '' && $name !== 'other',
        ));

        sort($engine);
        sort($canonical);

        $names = [...$engine, ...array_map(strtoupper(...), $canonical)];

        return $names === [] ? 'those privileges' : implode(', ', $names);
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'compares the project\'s configured runtime connection against the catalog: a project that has not told SQLens which connection is the runtime one gets no answer here rather than a guessed one',
            'reads the privilege, not its use. A runtime role that CAN create objects and never does is reported the same way, because the finding is about what a compromise of that role would reach',
        ];
    }
}
