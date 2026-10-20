<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L7;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\Settings\AbstractServerSettingRule;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A PostgreSQL server with `autovacuum = off`.
 *
 * {@see AutovacuumDisabledRule} reports one table switched off through its storage parameters. This
 * is the same state for every table at once, and a table's own `autovacuum_enabled = true` does not
 * override it: the autovacuum daemon does not run at all while the server setting is off.
 *
 * ## What it costs
 *
 * Dead rows are reclaimed by nobody, so every table grows and its file size stops saying anything
 * about the rows a rewrite would copy, which is what every time and space statement about a deploy
 * rests on. Row estimates go stale for the same reason, because autovacuum is what triggers most
 * `ANALYZE` runs. And the setting does not avoid the vacuum: a table that crosses
 * `autovacuum_freeze_max_age` is vacuumed anyway, by a worker that does not yield to a lock
 * request, and by then there is more to do.
 *
 * ## No MySQL twin
 *
 * InnoDB's purge cannot be switched off, and `innodb_stats_auto_recalc` decides whether optimizer
 * statistics are refreshed, not whether dead rows are reclaimed.
 */
final class AutovacuumOffRule extends AbstractServerSettingRule
{
    public function id(): string
    {
        return 'PG.L7.AUTOVACUUM_OFF';
    }

    public function level(): Level
    {
        return Level::PerformanceHeuristics;
    }

    /**
     * Performance, like the table-level rule: nothing is lost, while the space every table takes and
     * the worth of every estimate taken from it degrade.
     */
    public function category(): Category
    {
        return Category::Performance;
    }

    public function settingDriver(): string
    {
        return 'pgsql';
    }

    public function settingVariable(): string
    {
        return 'autovacuum';
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        if (strcasecmp($serverValue, $expectation->expectation ?? 'on') === 0) {
            return null;
        }

        return sprintf(
            'autovacuum is off for the whole server, so no table is vacuumed or analyzed on its own, '.
            'and a table that sets autovacuum_enabled = true does not change that. Dead rows pile up '.
            'in every table, so file sizes stop saying anything about the rows a rewrite would copy, '.
            'and row estimates go stale. It does not avoid the vacuum either: a table that crosses '.
            'autovacuum_freeze_max_age is vacuumed anyway, by a worker that does not yield to a lock '.
            'request, and by then there is more to do. %s',
            $this->remediation($expectation),
        );
    }
}
