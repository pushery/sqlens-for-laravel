<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L6;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Levels\Level;

/**
 * A MySQL server whose `sql_mode` omits `NO_ENGINE_SUBSTITUTION`.
 *
 * A `CREATE TABLE … ENGINE=InnoDB` against a server where InnoDB is unavailable then silently gets
 * the default engine instead. The migration succeeds, the table exists, and it has no transactions
 * and no foreign keys — which nothing in the schema file says.
 */
final class SqlModeMissingNoEngineSubstitutionRule extends AbstractSqlModeFlagRule
{
    public function id(): string
    {
        return 'MY.L6.SQL_MODE_ENGINE_SUBSTITUTION';
    }

    public function level(): Level
    {
        return Level::TypeIdiom;
    }

    public function category(): Category
    {
        return Category::Safety;
    }

    protected function requiredFlag(): string
    {
        return 'NO_ENGINE_SUBSTITUTION';
    }

    protected function consequence(): string
    {
        return 'A table asking for an engine the server cannot provide then silently gets the '
            .'default one instead: the migration succeeds, the table exists, and it may have neither '
            .'transactions nor foreign keys — none of which the schema file mentions.';
    }
}
