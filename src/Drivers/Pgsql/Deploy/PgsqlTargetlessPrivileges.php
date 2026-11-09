<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Deploy;

use Pushery\SQLens\Canonical\Identifier;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Capture\CapturedStatement;
use Pushery\SQLens\Deploy\PrivilegeClass;
use Pushery\SQLens\Deploy\PrivilegeRequirement;
use Pushery\SQLens\Deploy\RequiredPrivileges;
use Pushery\SQLens\Deploy\TargetlessPrivileges;
use Pushery\SQLens\Drivers\Pgsql\Canonical\PgsqlCanonicalization;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * What PostgreSQL asks of the migration role for the statements its classifier keeps without a
 * target.
 *
 * - A session setting needs nothing when it sets a parameter whose `context` in `pg_settings` is
 *   `user`: any role may set it for its own session or transaction. `SET ROLE` needs a membership,
 *   `SET SESSION AUTHORIZATION` and a parameter of the `superuser` context need more than a session
 *   has, and a parameter this list does not name stays unanswered rather than assumed harmless.
 * - A `RESET` needs nothing to put back every parameter the session set, the role it took on or the
 *   authorization it switched to: each returns to what the session started with, which any role
 *   may. For one parameter it asks what a `SET` of that parameter asks.
 * - `COMMENT ON TABLE` and `COMMENT ON COLUMN` need ownership of the table. Laravel writes one beside
 *   every `->change()`, next to the `ALTER TABLE` that needs the same ownership.
 * - `CREATE POLICY`, `ALTER POLICY` and `DROP POLICY` need ownership of the table they name.
 * - `CREATE FUNCTION`, `CREATE PROCEDURE`, `CREATE VIEW`, `CREATE MATERIALIZED VIEW` and `CREATE TYPE`
 *   need `CREATE` on the schema the object lands in. Replacing a routine or a view that exists
 *   already needs its ownership as well, which this answer does not ask.
 * - `CREATE TRIGGER` needs the `TRIGGER` privilege on the table it is put on, which the table's owner
 *   holds and another role can be given.
 * - `CREATE EXTENSION` is asked of the database: a trusted extension needs `CREATE` on it, any other
 *   one a superuser, and one that is installed already needs nothing.
 * - `GRANT` and `REVOKE` stay unanswered: ownership of the object or the grant option on it lets a
 *   role run them, and which of the two the role holds is not a question this check asks.
 * - A `DO` block stays unanswered, with what to do about it: what it needs depends on the code it
 *   runs, which no reading of the statement can tell. Its migration can answer it with
 *   `#[DoBlockPrivilege]`, which {@see RequiredPrivileges} puts in its place.
 */
final readonly class PgsqlTargetlessPrivileges implements TargetlessPrivileges
{
    /**
     * Parameters of the `user` context a migration has a reason to set, as PostgreSQL folds their
     * names. Any role may set each of them for its own session or transaction.
     */
    private const array USER_PARAMETERS = [
        'application_name', 'check_function_bodies', 'client_encoding', 'client_min_messages',
        'constraint_exclusion', 'datestyle', 'default_statistics_target', 'default_transaction_isolation',
        'default_transaction_read_only', 'hash_mem_multiplier', 'idle_in_transaction_session_timeout',
        'idle_session_timeout', 'intervalstyle', 'jit', 'lock_timeout', 'maintenance_work_mem',
        'max_parallel_maintenance_workers', 'max_parallel_workers_per_gather', 'row_security',
        'search_path', 'statement_timeout', 'synchronous_commit', 'temp_buffers', 'timezone',
        'transaction_timeout', 'work_mem',
    ];

    /** A name, quoted or bare, with the parts that qualify it. */
    private const string NAME = '(?:"(?:[^"]|"")*"|[^\s."(),;]+)(?:\s*\.\s*(?:"(?:[^"]|"")*"|[^\s."(),;]+))*';

    public function __construct(
        private PgsqlCanonicalization $canonicalization = new PgsqlCanonicalization,
    ) {}

    public function requirementsOf(CapturedStatement $statement): ?array
    {
        $sql = trim($statement->canonicalSql ?? $statement->rawSql);

        // Before the kind, because a `DO` block has none: the classifier keeps it unrecognized on
        // purpose, so that no rule takes code it cannot read for a statement that changes nothing.
        if (preg_match('/^DO\b/i', $sql) === 1) {
            return [PrivilegeRequirement::codeBlock(
                'privilege_requirement_underivable: a DO block runs code, and what the role must be '
                .'allowed to do depends on what that code does, which reading the statement cannot '
                .'tell. Name each right it needs with #[DoBlockPrivilege] on its migration, and the '
                .'check asks about those instead; a deploy that may go on without the answer waives '
                .'privilege_check_incomplete with --allow-undetermined or '
                .'sqlens.deploy.predeploy.allow_undetermined.',
            )];
        }

        return match ($statement->statementKind) {
            StatementKind::SessionSetting => $this->sessionSetting($sql),
            StatementKind::DdlOther => $this->otherDdl($sql),
            default => null,
        };
    }

    /** @return list<PrivilegeRequirement>|null */
    private function sessionSetting(string $sql): ?array
    {
        if (preg_match('/^RESET\b\s*(.*?)\s*;?$/is', $sql, $reset) === 1) {
            return $this->reset($reset[1]);
        }

        $setting = (string) preg_replace('/^SET\s+(?:(?:SESSION|LOCAL)\s+)?/i', '', $sql);

        // A role and an authorization are a change of identity, which a session cannot grant itself.
        if (preg_match('/^(?:ROLE|SESSION\s+AUTHORIZATION|AUTHORIZATION)\b/i', $setting) === 1) {
            return null;
        }

        // The modes of a transaction, the timing of its constraints and the time zone are any role's.
        if (preg_match('/^(?:TRANSACTION|CONSTRAINTS|CHARACTERISTICS\s+AS\s+TRANSACTION|TIME\s+ZONE)\b/i', $setting) === 1) {
            return [];
        }

        if (preg_match('/^("?)([A-Za-z_][A-Za-z0-9_]*)\1\s*(?:=|\bTO\b)/i', $setting, $parameter) !== 1) {
            return null;
        }

        return in_array(strtolower($parameter[2]), self::USER_PARAMETERS, true) ? [] : null;
    }

    /**
     * What a `RESET` of the given setting asks. `RESET ALL` puts back only what the session itself
     * set, and `RESET ROLE` and `RESET SESSION AUTHORIZATION` return to the identity it logged in
     * with, so none of them needs a right. A parameter is answered as its `SET` is, and a name the
     * list does not know stays unanswered.
     *
     * @return list<PrivilegeRequirement>|null
     */
    private function reset(string $setting): ?array
    {
        if (preg_match('/^(?:ALL|ROLE|SESSION\s+AUTHORIZATION|TIME\s+ZONE|TRANSACTION\s+ISOLATION\s+LEVEL)$/i', $setting) === 1) {
            return [];
        }

        if (preg_match('/^("?)([A-Za-z_][A-Za-z0-9_]*)\1$/', $setting, $parameter) !== 1) {
            return null;
        }

        return in_array(strtolower($parameter[2]), self::USER_PARAMETERS, true) ? [] : null;
    }

    /** @return list<PrivilegeRequirement>|null */
    private function otherDdl(string $sql): ?array
    {
        if (preg_match('/^COMMENT\s+ON\s+TABLE\s+('.self::NAME.')\s+IS\b/i', $sql, $comment) === 1) {
            return $this->ownershipOf($comment[1]);
        }

        // The last part names the column, and what stands before it names the table.
        if (preg_match('/^COMMENT\s+ON\s+COLUMN\s+('.self::NAME.')\s+IS\b/i', $sql, $comment) === 1) {
            return $this->ownershipOf($this->withoutLastPart($comment[1]));
        }

        if (preg_match('/^(?:CREATE|ALTER|DROP)\s+POLICY\s+(?:IF\s+EXISTS\s+)?(?:"(?:[^"]|"")*"|[^\s"]+)\s+ON\s+('.self::NAME.')/i', $sql, $policy) === 1) {
            return $this->ownershipOf($policy[1]);
        }

        // A routine, a view or a type lands in a schema, and creating one needs CREATE on it. An
        // argument list or a column list ends the name, since a name holds no parenthesis.
        if (preg_match('/^CREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE)\s+('.self::NAME.')/i', $sql, $routine) === 1) {
            return $this->creationOf($routine[1], SchemaObjectType::Routine);
        }

        if (preg_match('/^CREATE\s+(?:OR\s+REPLACE\s+)?(?:(?:TEMP|TEMPORARY)\s+)?(?:RECURSIVE\s+)?VIEW\s+('.self::NAME.')/i', $sql, $view) === 1) {
            return $this->creationOf($view[1], SchemaObjectType::View);
        }

        if (preg_match('/^CREATE\s+MATERIALIZED\s+VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?('.self::NAME.')/i', $sql, $view) === 1) {
            return $this->creationOf($view[1], SchemaObjectType::MaterializedView);
        }

        if (preg_match('/^CREATE\s+TYPE\s+('.self::NAME.')/i', $sql, $type) === 1) {
            return $this->creationOf($type[1], SchemaObjectType::Type);
        }

        // The events and their columns stand between the trigger's name and the table, and the
        // first `ON` after the name is the one that names the table.
        if (preg_match('/^CREATE\s+(?:OR\s+REPLACE\s+)?(?:CONSTRAINT\s+)?TRIGGER\s+(?:"(?:[^"]|"")*"|[^\s"]+)\s+.*?\bON\s+('.self::NAME.')/is', $sql, $trigger) === 1) {
            return $this->onTable($trigger[1], PrivilegeClass::Trigger);
        }

        if (preg_match('/^CREATE\s+EXTENSION\s+(?:IF\s+NOT\s+EXISTS\s+)?("(?:[^"]|"")*"|[^\s"(),;]+)/i', $sql, $extension) === 1) {
            return $this->creationOf($extension[1], SchemaObjectType::Extension);
        }

        if (preg_match('/^(?:GRANT|REVOKE)\b/i', $sql) === 1) {
            return [PrivilegeRequirement::underivable(
                '(unresolved)',
                SchemaObjectType::Table,
                'privilege_requirement_underivable: a GRANT or REVOKE may be run by the owner of its object '
                .'or by a role that holds the grant option on it, and which of the two the role is was not '
                .'asked, so whether it may run the statement is not answered here.',
            )];
        }

        return null;
    }

    /** @return list<PrivilegeRequirement>|null */
    private function ownershipOf(?string $table): ?array
    {
        return $this->onTable($table, PrivilegeClass::Ownership);
    }

    /** @return list<PrivilegeRequirement>|null */
    private function onTable(?string $table, PrivilegeClass $class): ?array
    {
        $identifier = $table === null ? null : Identifier::parse($table, $this->canonicalization);

        return $identifier instanceof Identifier
            ? [PrivilegeRequirement::of($identifier->canonical(), SchemaObjectType::Table, $class)]
            : null;
    }

    /** @return list<PrivilegeRequirement>|null */
    private function creationOf(string $name, SchemaObjectType $type): ?array
    {
        $identifier = Identifier::parse($name, $this->canonicalization);

        return $identifier instanceof Identifier
            ? [PrivilegeRequirement::of($identifier->canonical(), $type, PrivilegeClass::Create)]
            : null;
    }

    /** A qualified name without its last part, or null for a name that has only one. */
    private function withoutLastPart(string $name): ?string
    {
        preg_match_all('/"(?:[^"]|"")*"|[^\s."]+/', $name, $parts);

        return count($parts[0]) > 1 ? implode('.', array_slice($parts[0], 0, -1)) : null;
    }
}
