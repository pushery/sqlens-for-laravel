<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L5;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Drivers\Mysql\Rules\L6\AbstractSqlModeFlagRule;
use Pushery\SQLens\Levels\Level;

/**
 * A MySQL server whose `sql_mode` omits `STRICT_TRANS_TABLES`.
 *
 * The most expensive of the four, because the failure is a successful statement. Without it an
 * out-of-range number, an over-long string or an invalid date is TRUNCATED and the INSERT reports
 * success with a warning nobody reads. The application believes it stored what it sent.
 */
final class SqlModeMissingStrictTransTablesRule extends AbstractSqlModeFlagRule
{
    public function id(): string
    {
        return 'MY.L5.SQL_MODE_NOT_STRICT';
    }

    public function level(): Level
    {
        return Level::SchemaBasics;
    }

    public function category(): Category
    {
        return Category::Safety;
    }

    protected function requiredFlag(): string
    {
        return 'STRICT_TRANS_TABLES';
    }

    protected function consequence(): string
    {
        return 'An out-of-range number, an over-long string or an invalid date is then TRUNCATED and '
            .'the statement SUCCEEDS with a warning — so the application believes it stored what it '
            .'sent, and the shortened value is only found later by whoever notices the data is wrong.';
    }
}
