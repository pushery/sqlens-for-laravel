<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Catalog;

/**
 * The freeze threshold autovacuum applies to one table, as an SQL expression over its `pg_class` row.
 *
 * A table can carry its own `autovacuum_freeze_max_age` or `autovacuum_multixact_freeze_max_age` in
 * `reloptions`, and autovacuum takes the lower of it and the cluster's setting: a table's own value can
 * only move the line closer. Measured against the cluster's alone, a table with a lower value of its
 * own reads further from its horizon than the launcher sees it, which is the direction that stays silent.
 */
final readonly class FreezeThreshold
{
    public const string TRANSACTIONS = 'autovacuum_freeze_max_age';

    public const string MULTIXACTS = 'autovacuum_multixact_freeze_max_age';

    /**
     * The lower of the table's own setting and the cluster's, for the `pg_class` row aliased $class.
     *
     * @param  literal-string  $class
     * @param  self::TRANSACTIONS|self::MULTIXACTS  $setting
     * @return literal-string
     */
    public static function effective(string $class, string $setting): string
    {
        $cluster = "pg_catalog.current_setting('{$setting}')::bigint";

        return "least({$cluster}, coalesce((select o.option_value::bigint"
            ." from pg_catalog.pg_options_to_table({$class}.reloptions) o"
            ." where o.option_name = '{$setting}'), {$cluster}))";
    }
}
