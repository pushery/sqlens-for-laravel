<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L6;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\Settings\AbstractServerSettingRule;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A PostgreSQL server that starts every transaction read-only by default.
 *
 * ## What actually goes wrong
 *
 * With `default_transaction_read_only = on`, a transaction that does not say `READ WRITE` refuses
 * writes: an INSERT, an UPDATE or a DDL statement fails with `25006`. An application that expects to
 * write is then broken in a way that looks like a permissions problem and is not one.
 *
 * ## The part that makes this worth its own rule
 *
 * It changes what OTHER findings in the same run mean. A migration audit reasons about what a write
 * would do — which lock it takes, how long it holds it, whether it rewrites a table. On a server
 * where writes are refused before any of that, those statements are still true about the SQL and no
 * longer true about this instance. The finding therefore says so explicitly rather than reporting a
 * setting and leaving the reader to notice the implication, because a report that quietly changes
 * meaning is worse than one that is wrong out loud.
 *
 * ## Why it is separate from the isolation rule
 *
 * They read neighboring variables and are two independent statements. Under one id a single
 * ignore-list entry would silence both, and whoever added it could not say afterwards which of the
 * two they had accepted.
 */
final class DefaultTransactionReadOnlyRule extends AbstractServerSettingRule
{
    public function id(): string
    {
        return 'PG.L6.DEFAULT_TRANSACTION_READ_ONLY';
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
        return 'pgsql';
    }

    public function settingVariable(): string
    {
        return 'default_transaction_read_only';
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        if (strcasecmp($serverValue, $expectation->expectation ?? 'off') === 0) {
            return null;
        }

        return sprintf(
            'the server starts every transaction read-only by default (default_transaction_read_only '.
            '= %s), so a write that does not open its transaction READ WRITE fails with SQLSTATE '.
            '25006 — which reads like a permissions problem and is not one. Treat the rest of this '.
            'run accordingly: findings about what a write would cost are still true about the SQL '.
            'and are no longer true about this instance, because the write is refused before any of '.
            'it happens. A dedicated read replica held read-only on purpose is the expected case to '.
            'add to the ignore list, with the reason recorded there. %s',
            $serverValue,
            $this->remediation($expectation),
        );
    }
}
