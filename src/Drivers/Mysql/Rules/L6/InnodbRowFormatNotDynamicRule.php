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
 * A MySQL server whose `innodb_default_row_format` is not `DYNAMIC`.
 *
 * ## What actually goes wrong, and when
 *
 * With `COMPACT` or `REDUNDANT`, an InnoDB table created without an explicit `ROW_FORMAT` — which is
 * every table Laravel's schema builder makes, because it never emits one — gets the **767-byte**
 * index key prefix ceiling instead of 3072. Under the utf8mb4 default that is 191 characters, so the
 * first `$table->string('email')->unique()` (VARCHAR(255) at 4 bytes = 1020) aborts the migration
 * with `ERROR 1071 Specified key was too long`.
 *
 * The timing is the damage. It aborts MID-DEPLOY, leaving some migrations applied and some not, on a
 * server every other check called healthy.
 *
 * ## Why this is worth a rule rather than a workaround
 *
 * The field fix everyone reaches for is `Schema::defaultStringLength(191)` in a service provider.
 * That converts a one-line server misconfiguration into a permanent, application-wide narrowing of
 * every string column — invisible to whoever reads the migrations later, and carried forward onto
 * servers that never had the problem.
 *
 * ## What this rule does NOT report
 *
 * A server correctly handing out `DYNAMIC` while the catalog still holds tables created years ago
 * under an older default. There is nothing in the configuration to fix there, and reporting it as a
 * server-baseline violation would send a reader to a file that is already correct while never naming
 * the actual work — an `ALTER TABLE … ROW_FORMAT=DYNAMIC` rebuild per table. That is a separate
 * finding about the schema, and it belongs to a schema rule rather than to this one.
 */
final class InnodbRowFormatNotDynamicRule extends AbstractServerSettingRule
{
    public function id(): string
    {
        return 'MY.L6.INNODB_ROW_FORMAT_NOT_DYNAMIC';
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
        return 'innodb_default_row_format';
    }

    /**
     * The tables already on a legacy format — not to judge, but to size the problem.
     *
     * @return list<string>
     */
    #[Override]
    protected function requiredCrossFacts(): array
    {
        return [MysqlSettingCrossFactCollector::LEGACY_ROW_FORMAT_TABLES];
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        // MySQL reports this lower-case (`dynamic`) while the documentation and every config file
        // write it upper-case. Folded, because a rule flagging `dynamic` for not being `DYNAMIC`
        // would fire on the exact value the matrix asks for.
        if (strcasecmp(trim($serverValue), $expectation->expectation ?? 'DYNAMIC') === 0) {
            return null;
        }

        return sprintf(
            'the server creates InnoDB tables as %s rather than %s, so a table made without an '.
            'explicit ROW_FORMAT — which is every table Laravel\'s schema builder makes — gets the '.
            '767-byte index key prefix limit instead of 3072. Under utf8mb4 that is 191 characters, '.
            'so the first unique index on a string column fails with ERROR 1071, and it fails '.
            'MID-DEPLOY: some migrations applied, some not. The usual workaround, '.
            'Schema::defaultStringLength(191), turns a one-line server fix into a permanent '.
            'narrowing of every string column in the application. %s%s',
            $serverValue,
            $expectation->expectation ?? 'DYNAMIC',
            $this->remediation($expectation),
            $this->legacyTables($object),
        );
    }

    /**
     * How much of the existing schema is already on the old format.
     *
     * Stated either way. "Nothing is on it yet" means the server default is a hazard for the next
     * migration; a list means a rebuild is owed as well, and the two call for different plans.
     */
    private function legacyTables(SchemaObject $object): string
    {
        $tables = $this->crossFact($object, MysqlSettingCrossFactCollector::LEGACY_ROW_FORMAT_TABLES);

        return match ($tables === null || $tables === '') {
            true => ' No existing table in this schema carries the legacy format, so this is a hazard for '
                .'the next migration rather than a rebuild that is already owed.',
            false => ' Already on a legacy format and needing an ALTER TABLE … ROW_FORMAT=DYNAMIC rebuild: '.$tables.'.',
        };
    }
}
