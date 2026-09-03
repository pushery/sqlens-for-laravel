<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Catalog;

use Pushery\SQLens\Catalog\Degradation\CatalogArea;
use Pushery\SQLens\Contracts\CatalogPrivileges;

/**
 * What a PostgreSQL role must be able to read for an audit to mean what it says.
 *
 * Measured against a role holding nothing but `CONNECT`, on a real PostgreSQL 18 — and the result is
 * mostly good news worth stating: **`pg_class` and `pg_index` are world-readable**, so the core of a
 * reading works on a managed instance with no special grant at all. The gaps are narrower and more
 * specific than "you need a superuser", and naming them precisely is what keeps a managed-database
 * run from looking broken when it is merely bounded.
 *
 * The two shapes the same server uses to withhold, both measured:
 *
 * - **Loud.** `pg_hba_file_rules` refuses with `42501`. A reader meets an exception.
 * - **Silent.** `pg_settings` simply OMITS a superuser-only row — `data_directory` returns zero rows
 *   for an ordinary role and one row for a superuser, with no error either way. Nothing in the
 *   reading distinguishes that from a setting the server does not have, which is exactly why the
 *   question is asked in advance instead of inferred from an empty result afterwards.
 */
final readonly class PgsqlCatalogPrivileges implements CatalogPrivileges
{
    public function areas(array $schemas): array
    {
        return [
            // The core battery. World-readable in a stock PostgreSQL, so a `false` here means
            // something genuinely unusual — a hardened instance, or a revoked default — and the
            // audit that follows would be empty for a reason nobody would otherwise find.
            new CatalogArea(
                'relations, columns and indexes',
                "SELECT has_table_privilege('pg_catalog.pg_class', 'SELECT')
                    AND has_table_privilege('pg_catalog.pg_index', 'SELECT')
                    AND has_table_privilege('pg_catalog.pg_attribute', 'SELECT') AS ok",
                'the reading role cannot read pg_class, pg_attribute or pg_index, so an audit of this database would be empty rather than clean',
            ),
            new CatalogArea(
                'constraints and types',
                "SELECT has_table_privilege('pg_catalog.pg_constraint', 'SELECT')
                    AND has_table_privilege('pg_catalog.pg_type', 'SELECT') AS ok",
                'the reading role cannot read pg_constraint or pg_type, so nothing can be concluded about foreign keys, checks, domains or enums',
            ),
            // Statistics are the input to every rule that reasons about table SIZE. Withheld on
            // managed instances more often than the catalog itself, and a rule that quietly assumed
            // "small" would recommend a lock on a table with a hundred million rows.
            new CatalogArea(
                'table statistics',
                "SELECT has_table_privilege('pg_catalog.pg_statistic', 'SELECT') AS ok",
                'pg_statistic is not readable, so no rule may reason about table size or row estimates from this reading',
            ),
            // The silent one. Asked as "can you see a setting only a superuser sees", because the
            // server answers a missing privilege here with a missing ROW rather than an error.
            new CatalogArea(
                'restricted server settings',
                "SELECT count(*) > 0 AS ok FROM pg_settings WHERE name = 'data_directory'",
                'settings that require pg_read_all_settings are invisible to this role — they are silently ABSENT from pg_settings rather than refused, so a check that read one would see an empty answer and not an error',
            ),
        ];
    }
}
