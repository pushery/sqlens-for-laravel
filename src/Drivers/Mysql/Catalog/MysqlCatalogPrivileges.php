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
 */
final readonly class MysqlCatalogPrivileges implements CatalogPrivileges
{
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
