<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L6;

use Pushery\SQLens\Drivers\Mysql\Rules\Support\SqlModeFlags;
use Pushery\SQLens\Rules\Settings\AbstractServerSettingRule;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * The shared half of the four rules that judge a flag inside `sql_mode`.
 *
 * ## Why four rules and not one
 *
 * They are four independent claims about four different hazards, and a project may legitimately
 * accept one while wanting the others. Under a single id an ignore-list entry would silence all
 * four, and whoever added it could not say afterwards which one they had accepted — the same
 * argument that keeps the two `default_transaction_*` rules apart on PostgreSQL.
 *
 * ## What this base owns
 *
 * The parse, and the sentence structure. What it deliberately does NOT own is the consequence: each
 * flag fails differently, and a shared "this flag is missing" message would be the kind of finding
 * that tells a reader what is wrong without telling them why it matters.
 */
abstract class AbstractSqlModeFlagRule extends AbstractServerSettingRule
{
    public function settingDriver(): string
    {
        return 'mysql';
    }

    public function settingVariable(): string
    {
        return 'sql_mode';
    }

    /** The exact flag this rule requires, as the server spells it. */
    abstract protected function requiredFlag(): string;

    /** What goes wrong without it — the half a shared message could not carry. */
    abstract protected function consequence(): string;

    final protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        $flags = SqlModeFlags::parse($serverValue);

        if ($flags->has($this->requiredFlag())) {
            return null;
        }

        // An empty sql_mode is called out separately. It is a legal value and a deliberate-looking
        // one — somebody set it to '' — so reporting it as "one flag missing" would understate a
        // server running with every guard off at once.
        $context = $flags->isEmpty()
            ? 'the server sql_mode is EMPTY, so every mode-guarded behavior is off at once, including '
                .$this->requiredFlag()
            : sprintf('the server sql_mode does not include %s', $this->requiredFlag());

        return sprintf(
            '%s. %s Laravel sets sql_mode per connection from the connection\'s strict flag, so an '.
            'application may look correct while the SERVER hands this configuration to everything '.
            'else that connects — a queue worker with different config, a migration run by hand, a '.
            'reporting tool. %s',
            $context,
            $this->consequence(),
            $this->remediation($expectation),
        );
    }
}
