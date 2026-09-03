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
 * A MySQL server whose `default_storage_engine` is not InnoDB.
 *
 * ## What actually goes wrong
 *
 * A table created without an explicit `ENGINE` takes it. Under MyISAM that table has no
 * transactions, no foreign keys and no crash recovery — and none of those absences raise anything.
 * A migration wrapped in a transaction simply does not roll back; a foreign key silently is not
 * enforced; an unclean shutdown leaves the table needing repair.
 *
 * Laravel's schema builder emits `ENGINE` from `config('database.connections.mysql.engine')` when
 * one is configured, and nothing when it is not — which is the common case, and why the server value
 * decides.
 *
 * ## The reasoned pass, and why silence would be the wrong answer
 *
 * A server can have `default_storage_engine = MyISAM` while `disabled_storage_engines` names MyISAM.
 * The setting then looks wrong and cannot bite: no table can be created under an engine the server
 * refuses to load.
 *
 * Reporting nothing there would be indistinguishable from a rule that never ran, and reporting a
 * failure would send somebody to change a setting that is already harmless. So this is one of the
 * few rules that says `pass` OUT LOUD, with the reason — the ticket's own guardrail calls the
 * reasoned pass part of the statement rather than silence.
 */
final class DefaultStorageEngineNotInnodbRule extends AbstractServerSettingRule
{
    public function id(): string
    {
        return 'MY.L6.DEFAULT_STORAGE_ENGINE_NOT_INNODB';
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
        return 'default_storage_engine';
    }

    /** @return list<string> */
    #[Override]
    protected function requiredCrossFacts(): array
    {
        return [MysqlSettingCrossFactCollector::DISABLED_STORAGE_ENGINES];
    }

    protected function reasonedPass(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        if (strcasecmp(trim($serverValue), $expectation->expectation ?? 'InnoDB') === 0) {
            // Already correct. Nothing to excuse, and a pass here would report every healthy server
            // as news — which is how a report of findings turns into a report of everything.
            return null;
        }

        $disabled = $this->crossFact($object, MysqlSettingCrossFactCollector::DISABLED_STORAGE_ENGINES);

        if ($disabled === null || ! $this->refuses($disabled, $serverValue)) {
            return null;
        }

        return sprintf(
            'the server default storage engine is %s, which would normally be a finding — but '.
            'disabled_storage_engines refuses %s outright (%s), so no table can be created under it '.
            'and the setting cannot take effect. Reported as a pass rather than silently, because '.
            '"this looks wrong and cannot bite" is not something a reader can infer from an absent '.
            'finding. Correcting the default is still worth doing: it removes a trap for whoever '.
            'later shortens that refusal list.',
            $serverValue,
            $serverValue,
            $disabled,
        );
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        // Case-folded: a my.cnf saying `default_storage_engine=innodb` produces the same server
        // behavior, and flagging it would be a pure spelling false positive.
        if (strcasecmp(trim($serverValue), $expectation->expectation ?? 'InnoDB') === 0) {
            return null;
        }

        return sprintf(
            'the server creates tables as %s rather than %s when a migration does not name an '.
            'engine — and Laravel only names one when database.connections.mysql.engine is '.
            'configured, which is not the default. Such a table has no transactions, no foreign keys '.
            'and no crash recovery, and none of those absences raise anything: a migration wrapped '.
            'in a transaction simply does not roll back, and a foreign key is silently not enforced. %s',
            $serverValue,
            $expectation->expectation ?? 'InnoDB',
            $this->remediation($expectation),
        );
    }

    /** Whether the refusal list names this engine — matched per entry, never as a substring. */
    private function refuses(string $disabled, string $engine): bool
    {
        return array_any(
            explode(',', $disabled),
            static fn (string $candidate): bool => strcasecmp(trim($candidate), trim($engine)) === 0,
        );
    }
}
