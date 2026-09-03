<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L5;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Drivers\Mysql\Rules\L6\AbstractSqlModeFlagRule;
use Pushery\SQLens\Levels\Level;

/**
 * A MySQL server whose `sql_mode` omits `ERROR_FOR_DIVISION_BY_ZERO`.
 *
 * Division by zero then yields NULL instead of raising. A NULL flowing into an average, a ratio or a
 * money column is the kind of wrong that survives review: nothing failed, and the result merely
 * looks like missing data rather than like a defect.
 */
final class SqlModeMissingErrorForDivisionByZeroRule extends AbstractSqlModeFlagRule
{
    public function id(): string
    {
        return 'MY.L5.SQL_MODE_DIVISION_BY_ZERO_SILENT';
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
        return 'ERROR_FOR_DIVISION_BY_ZERO';
    }

    protected function consequence(): string
    {
        return 'Division by zero then yields NULL instead of raising, and a NULL flowing into an '
            .'average, a ratio or a money column reads as missing data rather than as a defect — so '
            .'it survives review and lands in a report somebody trusts.';
    }
}
