<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L5;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Drivers\Mysql\Rules\L6\AbstractSqlModeFlagRule;
use Pushery\SQLens\Levels\Level;

/**
 * A MySQL server whose `sql_mode` omits `ERROR_FOR_DIVISION_BY_ZERO`.
 *
 * ## What the flag governs, measured on 8.4.10 rather than read off the manual
 *
 * | statement | flag off | flag on, with a strict mode |
 * |---|---|---|
 * | `SELECT 1/0` | NULL, no warning | NULL, plus warning 1365 |
 * | `INSERT` into a nullable column | accepted, stores NULL, no warning | error 1365 |
 * | `UPDATE` to a nullable column | accepted, stores NULL | error 1365 |
 * | `INSERT` into a NOT NULL column | error 1048, "column cannot be null" | error 1365 |
 *
 * **A NULL in a report is the one case the flag does not fix.** A `SELECT` keeps returning NULL
 * with the flag on; the manual is explicit, and the measurement above agrees. Recommending the
 * setting by that harm would describe something it does not prevent, and a reader who set it and
 * still found a NULL in an average would conclude the checker was wrong about something.
 *
 * The flag governs the **write** path, and that is the more valuable half anyway: a stored NULL
 * outlives the query that made it, and nothing downstream can tell it from a NULL somebody meant.
 *
 * **The last row is why the flag is worth setting even where a column forbids NULL.** Without
 * it, MySQL refuses the write for the wrong reason — "column cannot be null" is a complaint about
 * the column, and it sends the reader to the schema rather than to the arithmetic.
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
        return 'With this flag and a strict mode, a division by zero in a WRITING statement is an '
            .'error; in a SELECT it stays NULL and gains a warning. So what the flag prevents is a '
            .'NULL being STORED: without it an INSERT or UPDATE writing 1/0 into a nullable column '
            .'is accepted with no warning at all, and that NULL then reads as missing data rather '
            .'than as a defect — it survives review and lands in a report somebody trusts. On a NOT '
            .'NULL column the write fails either way, but without the flag it fails as "column '
            .'cannot be null", which sends the reader to the schema instead of the arithmetic.';
    }
}
