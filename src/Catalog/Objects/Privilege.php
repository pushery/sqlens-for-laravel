<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Objects;

/**
 * One privilege, in the vocabulary both engines are mapped into.
 *
 * The cases are PostgreSQL's set because it is the smaller and better-defined one, and every MySQL
 * privilege that means the same thing maps onto the same case: `Select` is `SELECT` on both. What
 * MySQL has and PostgreSQL does not — `DROP`, `ALTER`, `INDEX`, `PROCESS`, the dynamic privileges —
 * arrives as {@see self::Other} carrying its own name, which is the honest answer: pretending
 * `PROCESS` is a PostgreSQL privilege would let a rule written for one engine draw a conclusion on
 * the other that nobody checked.
 *
 * A rule asks `has(Privilege::Create)` and gets the same answer on both engines. That is the whole
 * point of this type, and the reason no rule ever sees an ACL string.
 */
enum Privilege: string
{
    case Select = 'select';
    case Insert = 'insert';
    case Update = 'update';
    case Delete = 'delete';
    case Truncate = 'truncate';
    case References = 'references';
    case Trigger = 'trigger';
    case Execute = 'execute';
    case Usage = 'usage';

    /** Create objects in a schema or database — the privilege the least-privilege rules are about. */
    case Create = 'create';

    case Connect = 'connect';
    case Temporary = 'temporary';

    /** PostgreSQL 16+: run maintenance commands (`VACUUM`, `ANALYZE`, `REINDEX`) without ownership. */
    case Maintain = 'maintain';

    /** PostgreSQL 15+: set a server parameter — `SET` on a `pg_parameter_acl` entry. */
    case Set = 'set';

    /** PostgreSQL 15+: change a parameter through `ALTER SYSTEM`. */
    case AlterSystem = 'alter_system';

    /**
     * A privilege this vocabulary has no case for, keeping its engine's own name.
     *
     * Not a bucket to be ignored: a rule that counts privileges must count these too, and one that
     * judges a specific privilege must not silently match them. That is why the name travels on the
     * grant rather than being folded away here.
     */
    case Other = 'other';

    /**
     * The case a PostgreSQL `aclexplode().privilege_type` names.
     *
     * `aclexplode` is used rather than parsing `relacl` text: the ACL string format
     * (`grantee=privs/grantor`, with `*` marking a grantable one) is a parser nobody should write
     * twice, and the server already has one.
     */
    public static function fromPostgres(string $privilegeType): self
    {
        return match (strtoupper($privilegeType)) {
            'SELECT' => self::Select,
            'INSERT' => self::Insert,
            'UPDATE' => self::Update,
            'DELETE' => self::Delete,
            'TRUNCATE' => self::Truncate,
            'REFERENCES' => self::References,
            'TRIGGER' => self::Trigger,
            'EXECUTE' => self::Execute,
            'USAGE' => self::Usage,
            'CREATE' => self::Create,
            'CONNECT' => self::Connect,
            'TEMPORARY', 'TEMP' => self::Temporary,
            'MAINTAIN' => self::Maintain,
            'SET' => self::Set,
            'ALTER SYSTEM' => self::AlterSystem,
            default => self::Other,
        };
    }

    /**
     * The case a MySQL grant-table column or dynamic privilege names.
     *
     * MySQL spells them as `Select_priv`-style column names in `mysql.db` / `mysql.tables_priv` and
     * as bare strings in `mysql.global_grants`, so both spellings are normalized here rather than at
     * two call sites that would drift.
     */
    public static function fromMysql(string $name): self
    {
        $normalized = strtoupper(str_replace(['_priv', '_PRIV'], '', $name));

        return match ($normalized) {
            'SELECT' => self::Select,
            'INSERT' => self::Insert,
            'UPDATE' => self::Update,
            'DELETE' => self::Delete,
            'REFERENCES' => self::References,
            'TRIGGER' => self::Trigger,
            'EXECUTE' => self::Execute,
            'CREATE' => self::Create,
            // `CREATE TEMPORARY TABLES` is MySQL's spelling of the same power PostgreSQL calls
            // `TEMPORARY`, and a rule about scratch tables must find both.
            'CREATE_TMP_TABLE', 'CREATE TEMPORARY TABLES' => self::Temporary,
            default => self::Other,
        };
    }
}
