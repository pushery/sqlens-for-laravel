<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Catalog;

use Pushery\SQLens\Catalog\Degradation\CatalogArea;
use Pushery\SQLens\Contracts\CatalogPrivileges;

/**
 * What a MySQL account must be able to see for an audit to mean what it says.
 *
 * MySQL has no equivalent of PostgreSQL's world-readable catalog, and the difference is not academic.
 * Measured on a real MySQL 8.4 with an account holding nothing but `USAGE`: the same
 * `information_schema.TABLES` query that returns a database's tables to `root` returns **zero rows**
 * to that account. No error. No warning. A clean, empty, complete-looking audit of a database the
 * reader could not see — the single most dangerous shape in this package's problem space, because
 * the reading itself SUCCEEDED.
 *
 * So the visibility question is asked directly, against the schemas the run will actually cover, and
 * its answer is a count rather than a privilege flag: `SHOW GRANTS` would say what was granted, and
 * what matters is what is visible.
 *
 * ## Why an empty database does not trip it
 *
 * A database with no tables also answers zero. The probe therefore asks about the SCHEMA rather than
 * its tables: a schema the account cannot see is absent from `information_schema.SCHEMATA` entirely,
 * while an empty-but-visible schema is present. That distinguishes "you may not look" from "there is
 * nothing to see", which is the distinction the whole three-valued model rests on.
 *
 * ## Why a visible database is not yet a visible reading
 *
 * A database is in `SCHEMATA` as soon as the account holds any right in it, a right on one table
 * included, and `TABLES` then lists that table and no other. Measured on MySQL 8.0.36: an account
 * with `SELECT` on one of two tables saw the database, and one table. So the account's own grants
 * are asked as well. A table- or column-level grant in an audited database, with no grant on the
 * whole database and no global grant that reaches tables, is a reading of single tables, and it is
 * named rather than taken for the database.
 *
 * The privilege views list what was granted to the account itself, not what reaches it through a
 * role, so an account whose table-level rights come through a role is not recognized here.
 */
final readonly class MysqlCatalogPrivileges implements CatalogPrivileges
{
    /**
     * The connecting account in the spelling of the privilege views' `GRANTEE`, `'user'@'host'`.
     *
     * The host is everything after the last `@`, because a host cannot hold one and a user name can.
     */
    private const string GRANTEE = "CONCAT('''', LEFT(CURRENT_USER(), CHAR_LENGTH(CURRENT_USER()) - CHAR_LENGTH(SUBSTRING_INDEX(CURRENT_USER(), '@', -1)) - 1), '''@''', SUBSTRING_INDEX(CURRENT_USER(), '@', -1), '''')";

    /** The privileges that make a table visible when they are held on its database or globally. */
    private const string TABLE_PRIVILEGES = "'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'REFERENCES', 'INDEX', 'ALTER', 'CREATE VIEW', 'SHOW VIEW', 'TRIGGER'";

    public function areas(array $schemas): array
    {
        if ($schemas === []) {
            return [];
        }

        $placeholders = implode(', ', array_fill(0, count($schemas), '?'));

        return [
            new CatalogArea(
                'the audited databases',
                sprintf(
                    'SELECT COUNT(*) = %d AS ok FROM information_schema.SCHEMATA WHERE SCHEMA_NAME IN (%s)',
                    count($schemas),
                    $placeholders,
                ),
                'at least one audited database is invisible to this account — information_schema is filtered by privilege, so the reading would come back EMPTY and look like a clean audit rather than an impossible one',
                $schemas,
            ),
            new CatalogArea(
                'every table of the audited databases',
                'SELECT COUNT(*) = 0 AS ok FROM ('
                .'SELECT TABLE_SCHEMA AS s FROM information_schema.TABLE_PRIVILEGES WHERE GRANTEE = '.self::GRANTEE.' AND TABLE_SCHEMA IN ('.$placeholders.')'
                .' UNION SELECT TABLE_SCHEMA FROM information_schema.COLUMN_PRIVILEGES WHERE GRANTEE = '.self::GRANTEE.' AND TABLE_SCHEMA IN ('.$placeholders.')'
                .') AS single_tables'
                .' WHERE NOT EXISTS (SELECT 1 FROM information_schema.USER_PRIVILEGES u WHERE u.GRANTEE = '.self::GRANTEE.' AND u.PRIVILEGE_TYPE IN ('.self::TABLE_PRIVILEGES.'))'
                .' AND NOT EXISTS (SELECT 1 FROM information_schema.SCHEMA_PRIVILEGES d WHERE d.GRANTEE = '.self::GRANTEE.' AND single_tables.s LIKE d.TABLE_SCHEMA AND d.PRIVILEGE_TYPE IN ('.self::TABLE_PRIVILEGES.'))',
                'this account holds rights on single tables of an audited database and on nothing wider, so information_schema lists only those tables — a table the reading does not list is not audited, and the reading would look complete',
                [...$schemas, ...$schemas],
            ),
            // performance_schema is off on some managed instances and denied on others; both end an
            // audit's ability to say anything about live statement behavior, and both are ordinary
            // rather than faults.
            new CatalogArea(
                'performance_schema',
                'SELECT COUNT(*) > 0 AS ok FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = \'performance_schema\'',
                'performance_schema is disabled or not visible to this account, so nothing can be concluded from live statement instrumentation',
            ),
        ];
    }
}
