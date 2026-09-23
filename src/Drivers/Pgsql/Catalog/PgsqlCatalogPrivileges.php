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
                "SELECT pg_catalog.has_table_privilege('pg_catalog.pg_class', 'SELECT')
                    AND pg_catalog.has_table_privilege('pg_catalog.pg_index', 'SELECT')
                    AND pg_catalog.has_table_privilege('pg_catalog.pg_attribute', 'SELECT') AS ok",
                'the reading role cannot read pg_class, pg_attribute or pg_index, so an audit of this database would be empty rather than clean',
            ),
            new CatalogArea(
                'constraints and types',
                "SELECT pg_catalog.has_table_privilege('pg_catalog.pg_constraint', 'SELECT')
                    AND pg_catalog.has_table_privilege('pg_catalog.pg_type', 'SELECT') AS ok",
                'the reading role cannot read pg_constraint or pg_type, so nothing can be concluded about foreign keys, checks, domains or enums',
            ),
            // Statistics are the input to every rule that reasons about table size. A rule that quietly
            // assumed "small" would recommend a lock on a table with a hundred million rows.
            //
            // The probe reads `pg_stat_all_tables`, because that is what the size and estimate readers
            // use, together with `pg_class.reltuples` and `pg_relation_size()`. It does not ask about
            // `pg_statistic`: nothing in this package reads it, and it is deliberately not public (the
            // user-facing view is `pg_stats`). Measured on PostgreSQL 18.0, for a role holding exactly
            // `pg_monitor`, the role the README recommends:
            //
            //   pg_statistic        SELECT  false
            //   pg_class            SELECT  true
            //   pg_stats            SELECT  true
            //   pg_stat_all_tables  SELECT  true    <- what the readers use
            //
            // Asking about `pg_statistic` would report the snapshot as partial and emit
            // `AUDIT.CATALOG.UNREAD.INSUFFICIENT_PRIVILEGE` saying "no rule may reason about table size"
            // on every managed instance, while the size rules read what they need. Under
            // `strict_undetermined`, which this package recommends, a least-privilege audit could then
            // never go green.
            //
            // It is a real read rather than `has_table_privilege`, which is not a style choice:
            // that function reports the ACL of the relation, and for a view over a privileged function it
            // can say yes where the read still fails. Measured on the same server: a `pg_read_all_data`
            // role has `has_table_privilege('pg_hba_file_rules','SELECT') = true` and selecting from it
            // fails with "permission denied for function pg_hba_file_rules". `PrivilegeProbe` catches a
            // throwing probe and records it as a skip, so the honest question is the read itself.
            new CatalogArea(
                'table statistics',
                'SELECT pg_catalog.count(*) >= 0 AS ok FROM pg_catalog.pg_stat_all_tables',
                'the per-table statistics views are not readable, so no rule may reason about table size or row estimates from this reading',
            ),
            // The silent one. Asked as "can you see a setting only a superuser sees", because the
            // server answers a missing privilege here with a missing ROW rather than an error.
            new CatalogArea(
                'restricted server settings',
                "SELECT pg_catalog.count(*) > 0 AS ok FROM pg_settings WHERE name = 'data_directory'",
                'settings that require pg_read_all_settings are invisible to this role — they are silently ABSENT from pg_settings rather than refused, so a check that read one would see an empty answer and not an error',
            ),
        ];
    }
}
