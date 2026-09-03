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
 * A MySQL server running with `explicit_defaults_for_timestamp = OFF`.
 *
 * ## What actually goes wrong
 *
 * With it off, MySQL applies a set of legacy behaviors to `TIMESTAMP` columns that nothing in the
 * migration asked for:
 *
 * - the FIRST `TIMESTAMP` column in a table silently acquires `DEFAULT CURRENT_TIMESTAMP ON UPDATE
 *   CURRENT_TIMESTAMP`, so a column declared as a plain timestamp rewrites itself on every UPDATE;
 * - a `TIMESTAMP` column is `NOT NULL` unless declared nullable, and assigning `NULL` to it stores
 *   the current time rather than raising.
 *
 * The second is the one that costs an afternoon. A column that stores "now" when the application
 * writes `null` looks, in the data, exactly like a column the application filled deliberately — so
 * the bug is invisible in the table and only shows up when somebody asks why a record nobody touched
 * has a fresh timestamp.
 *
 * ## Why the schema does not show it
 *
 * The added default is applied by the SERVER at table-creation time, so it is not in the migration
 * anybody reviews. Two servers with different settings produce different tables from the same file,
 * which breaks the premise this package is built on — and neither table looks wrong on its own.
 *
 * MySQL 8.4 ships with it ON, so a server carrying OFF is either an explicit opt-out or a
 * configuration inherited from a 5.x-era deployment where OFF was the default.
 */
final class ExplicitDefaultsForTimestampOffRule extends AbstractServerSettingRule
{
    public function id(): string
    {
        return 'MY.L6.EXPLICIT_DEFAULTS_FOR_TIMESTAMP_OFF';
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
        return 'explicit_defaults_for_timestamp';
    }

    /**
     * The columns this setting already affects, which is what turns the finding into work somebody
     * can do today rather than a warning about a flag.
     *
     * Declared rather than read ad hoc so the base enforces the rung that matters: a catalog that
     * could not be read is not a catalog with nothing in it.
     *
     * @return list<string>
     */
    #[Override]
    protected function requiredCrossFacts(): array
    {
        return [MysqlSettingCrossFactCollector::TIMESTAMP_AUTO_UPDATE_COLUMNS];
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        // Folded on both sides, because MySQL spells this value differently depending on how it is
        // asked. Measured on 8.4.10: performance_schema and SHOW both answer `ON`, while the
        // `@@global.` syntax answers `1`. The reader only ever takes the first two, so the WORD is
        // what arrives here — but the matrix expectation, an operator's my.cnf and any hand-written
        // comparison may all carry the digit, and a rule comparing raw strings would then flag a
        // correctly configured server.
        //
        // The first version of this comment had it backwards and claimed performance_schema answers
        // the digit. The live-server test caught it, which is the entire argument for testing a
        // reader against a server rather than against what its documentation implies.
        if ($this->isOn($serverValue) === $this->isOn($expectation->expectation ?? 'ON')) {
            return null;
        }

        return sprintf(
            'the server has explicit_defaults_for_timestamp = %s, so it applies legacy TIMESTAMP '.
            'behavior that no migration asked for: the first TIMESTAMP column in a table silently '.
            'gains DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP and rewrites itself on '.
            'every UPDATE, and assigning NULL to a TIMESTAMP column stores the current time instead '.
            'of raising. The second is invisible in the data — a column that holds "now" because the '.
            'application wrote null looks exactly like one it filled deliberately. The server applies '.
            'this at table-creation time, so it is in none of the migrations anybody reviews, and two '.
            'servers configured differently produce different tables from the same file. %s',
            $serverValue,
            $this->remediation($expectation),
        ).$this->affectedColumns($object);
    }

    /**
     * The concrete half: which columns already carry the implicit `ON UPDATE CURRENT_TIMESTAMP`.
     *
     * An empty list is stated OUT LOUD rather than left as silence. "No column is affected yet" is a
     * genuinely different situation from a table full of them — it means the setting is a hazard for
     * the next migration rather than a bug in today's data — and a finding that simply omitted the
     * sentence would leave a reader unable to tell which of the two they are in.
     */
    private function affectedColumns(SchemaObject $object): string
    {
        $columns = $this->crossFact($object, MysqlSettingCrossFactCollector::TIMESTAMP_AUTO_UPDATE_COLUMNS);

        return match ($columns === null || $columns === '') {
            true => ' No column in this schema carries the implicit ON UPDATE CURRENT_TIMESTAMP yet, so this '
                .'is a hazard for the next migration rather than a defect in existing data.',
            false => ' Already affected in this schema: '.$columns.'.',
        };
    }

    /** `ON`/`OFF` from both reader paths, `1`/`0` from the `@@` syntax and from config files. */
    private function isOn(string $value): bool
    {
        return in_array(strtoupper(trim($value)), ['1', 'ON', 'TRUE', 'YES'], true);
    }
}
