<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\Support;

use Pushery\SQLens\Canonical\CanonicalName;
use Pushery\SQLens\Canonical\StatementKind;

/**
 * Whether an `ALTER TABLE` takes nothing stronger than SHARE UPDATE EXCLUSIVE: the forms of it that no
 * read and no write waits behind.
 *
 * Two kinds of action qualify. `VALIDATE CONSTRAINT` takes SHARE UPDATE EXCLUSIVE on the table, and
 * ROW SHARE on the table a foreign key references; it is the second step recommended after
 * `NOT VALID`, and a reading that counted it with the ACCESS EXCLUSIVE forms would flag the migration
 * that follows that advice. And `SET (…)` or `RESET (…)` of the maintenance storage parameters —
 * `fillfactor`, `toast_tuple_target`, `parallel_workers` and the vacuum family, each of the vacuum
 * ones also under `toast.` — take the same lock, measured parameter by parameter on PostgreSQL 18.4.
 * Any other parameter counts as the ACCESS EXCLUSIVE it may take: `user_catalog_table` does.
 *
 * Two facts decide it. The classifier gives these statements the kind `AlterTable`, and every action
 * in the statement is one of the above: one `ADD COLUMN` beside them takes ACCESS EXCLUSIVE for the
 * whole statement.
 */
final class ShareUpdateExclusiveAlter
{
    private const string NAME = '(?:'.CanonicalName::PATTERN.')';

    /** A storage parameter PostgreSQL changes under SHARE UPDATE EXCLUSIVE. */
    private const string PARAMETER = '(?:fillfactor|toast_tuple_target|parallel_workers'
        .'|(?:toast\.)?(?:autovacuum_\w+|vacuum_index_cleanup|vacuum_truncate|vacuum_max_eager_freeze_failure_rate|log_autovacuum_min_duration))';

    private const string ACTION = '(?:VALIDATE CONSTRAINT '.self::NAME
        .'|SET \(\s*'.self::PARAMETER.'\s*=\s*[^,()]+(?:\s*,\s*'.self::PARAMETER.'\s*=\s*[^,()]+)*\s*\)'
        .'|RESET \(\s*'.self::PARAMETER.'(?:\s*,\s*'.self::PARAMETER.')*\s*\))';

    private const string ONLY = '/^ALTER TABLE (?:IF EXISTS )?(?:ONLY )?'.self::NAME.'(?:\.'.self::NAME.')? '
        .self::ACTION.'(?:\s*,\s*'.self::ACTION.')*$/i';

    /** Whether this statement takes nothing stronger than SHARE UPDATE EXCLUSIVE. */
    public static function only(?StatementKind $kind, string $canonical): bool
    {
        return $kind === StatementKind::AlterTable && preg_match(self::ONLY, $canonical) === 1;
    }
}
