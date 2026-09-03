<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Deploy;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Contracts\ReadsWriteAcceptance;
use Pushery\SQLens\Deploy\Checks\PreflightStateUnreadable;
use Pushery\SQLens\Deploy\WriteAcceptance;

/**
 * MySQL's answer to "will this instance accept writes".
 *
 * Moved here from `ReadOnlyTargetCheck` for the reason its PostgreSQL sibling states: the check
 * branched on the driver, which is a driver decision inside the core.
 */
final readonly class MysqlWriteAcceptance implements ReadsWriteAcceptance
{
    #[RawSql(reason: 'reads @@read_only and @@super_read_only; a session variable is not something a query builder can name')]
    public function writeAcceptance(ReaderSession $session): WriteAcceptance
    {
        $row = $session->read(static fn (Connection $db): array => $db->select(
            'select @@super_read_only as super_read_only, @@read_only as read_only',
        ))[0] ?? null;

        if (! is_object($row)) {
            throw new PreflightStateUnreadable('the instance answered nothing about its write state');
        }

        // `super_read_only` first: it is the stronger setting and it implies the weaker one, so
        // naming `read_only` when both are on would send an operator to change the flag that is not
        // the one holding the door shut.
        if ($this->text($row, 'super_read_only') === '1') {
            return WriteAcceptance::refused(
                'super_read_only',
                'refusing writes from every account, including ones holding SUPER',
            );
        }

        if ($this->text($row, 'read_only') === '1') {
            return WriteAcceptance::refused(
                'read_only',
                'refusing writes from accounts without SUPER — which the migration account may or may not hold',
            );
        }

        return WriteAcceptance::accepted();
    }

    /** As its PostgreSQL sibling: an uninterpretable value reads as "not on", never as a verdict. */
    private function text(object $row, string $key): string
    {
        $value = $row->{$key} ?? null;

        return is_scalar($value) ? (string) $value : '';
    }
}
