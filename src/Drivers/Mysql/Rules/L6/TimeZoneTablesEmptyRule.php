<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L6;

use Override;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Drivers\Mysql\Catalog\MysqlSettingCrossFactCollector;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\Settings\AbstractServerSettingRule;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A MySQL server running a NAMED time zone while its timezone tables are empty.
 *
 * ## Why this is a separate rule from the one beside it
 *
 * {@see TimeZoneNotUtcRule} judges WHICH zone the server is on — an idiom question. This one judges
 * whether the server can resolve a named zone at all, which is a misconfiguration. One rule id
 * carries one category, and folding a `safety` finding into an `idiom` one would put it in the wrong
 * band for whoever gates on categories.
 *
 * ## What a fresh install actually does
 *
 * `mysql.time_zone_name` exists and is EMPTY until somebody runs `mysql_tzinfo_to_sql`. Measured on
 * this package's own MySQL 8.4: with the tables empty, `CONVERT_TZ('…','UTC','+00:00')` returns NULL
 * rather than raising, so a query that looks correct silently produces nothing.
 *
 * ## Why the trigger is narrower than it first appears
 *
 * Also measured: with the tables empty the server REFUSES to adopt a named zone —
 * `SET time_zone = 'Europe/Vienna'` answers `ERROR 1298 Unknown or incorrect time zone`. So this
 * state does not arise by setting the value; it arises the other way round, when a server that had
 * the tables loses them — a `mysql` schema restored from a dump that omitted them, an upgrade that
 * did not re-import, a container image rebuilt without the step.
 *
 * That makes the finding rare and worth keeping: a rare state nobody checks for is exactly the one
 * that survives to production. The rule stays silent on an offset value, which is the ordinary
 * configuration and carries no such dependency.
 */
final class TimeZoneTablesEmptyRule extends AbstractServerSettingRule
{
    public function id(): string
    {
        return 'MY.L6.TIME_ZONE_TABLES_EMPTY';
    }

    public function level(): Level
    {
        return Level::TypeIdiom;
    }

    public function category(): Category
    {
        return Category::Safety;
    }

    public function settingDriver(): string
    {
        return 'mysql';
    }

    public function settingVariable(): string
    {
        return 'time_zone';
    }

    /** @return list<string> */
    #[Override]
    protected function requiredCrossFacts(): array
    {
        return [MysqlSettingCrossFactCollector::TIME_ZONE_TABLES_LOADED];
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        if (! $this->isNamedZone($serverValue)) {
            // An offset carries no dependency on the tables, and SYSTEM defers to the host rather
            // than to them. Reporting either would be noise about a server that cannot have this
            // problem — the FP discipline the ticket asks for.
            return null;
        }

        $loaded = (int) $this->crossFact($object, MysqlSettingCrossFactCollector::TIME_ZONE_TABLES_LOADED);

        if ($loaded > 0) {
            return null;
        }

        return sprintf(
            'the server time_zone is the named zone %s, and mysql.time_zone_name holds no rows — so '.
            'the server cannot resolve a named zone at all. CONVERT_TZ with a named source returns '.
            'NULL rather than raising, which means a query that looks correct silently produces '.
            'nothing. A fresh install ships those tables EMPTY; they are populated by running '.
            'mysql_tzinfo_to_sql, and a server that once had them can lose them to a mysql-schema '.
            'restore that omitted them or an upgrade that did not re-import. Load them, or move the '.
            'server to the offset form, which needs nothing loaded.',
            $serverValue,
        );
    }

    /**
     * Whether this value depends on the timezone tables.
     *
     * An offset (`+00:00`, `-05:30`) is resolved arithmetically and `SYSTEM` defers to the host —
     * neither touches the tables. Everything else is a name that has to be looked up.
     */
    private function isNamedZone(string $value): bool
    {
        $trimmed = trim($value);

        return $trimmed !== ''
            && strcasecmp($trimmed, 'SYSTEM') !== 0
            && preg_match('/^[+-]\d{1,2}:\d{2}$/', $trimmed) !== 1;
    }
}
