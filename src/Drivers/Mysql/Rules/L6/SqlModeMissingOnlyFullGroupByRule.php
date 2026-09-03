<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L6;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Levels\Level;

/**
 * A MySQL server whose `sql_mode` omits `ONLY_FULL_GROUP_BY`.
 *
 * A `GROUP BY` may then select columns that are not grouped and not aggregated, and MySQL returns an
 * arbitrary row's value for them. It is not random enough to notice in development and not stable
 * enough to rely on — the query works, and the number is picked from a row nobody chose.
 */
final class SqlModeMissingOnlyFullGroupByRule extends AbstractSqlModeFlagRule
{
    public function id(): string
    {
        return 'MY.L6.SQL_MODE_LOOSE_GROUP_BY';
    }

    public function level(): Level
    {
        return Level::TypeIdiom;
    }

    public function category(): Category
    {
        return Category::Idiom;
    }

    protected function requiredFlag(): string
    {
        return 'ONLY_FULL_GROUP_BY';
    }

    protected function consequence(): string
    {
        return 'A GROUP BY may then select a column that is neither grouped nor aggregated, and the '
            .'server returns an arbitrary row\'s value for it — not random enough to notice in '
            .'development, not stable enough to rely on.';
    }
}
