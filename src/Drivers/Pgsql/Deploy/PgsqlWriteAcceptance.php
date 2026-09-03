<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Deploy;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Contracts\ReadsWriteAcceptance;
use Pushery\SQLens\Deploy\Checks\PreflightStateUnreadable;
use Pushery\SQLens\Deploy\WriteAcceptance;

/**
 * PostgreSQL's answer to "will this instance accept writes".
 *
 * Moved here from `ReadOnlyTargetCheck`, which asked it behind a `$context->driver === 'mysql'`
 * branch — a driver decision inside the core. The queries and the ordering are the
 * ones that were already there; what changed is who knows them.
 */
final readonly class PgsqlWriteAcceptance implements ReadsWriteAcceptance
{
    #[RawSql(reason: 'reads pg_is_in_recovery() and default_transaction_read_only -- a server function and a GUC, neither of which has a builder expression')]
    public function writeAcceptance(ReaderSession $session): WriteAcceptance
    {
        $row = $session->read(static fn (Connection $db): array => $db->select(
            'select pg_is_in_recovery() as in_recovery,'
            .' current_setting(\'default_transaction_read_only\') as read_only',
        ))[0] ?? null;

        if (! is_object($row)) {
            throw new PreflightStateUnreadable('the instance answered nothing about its write state');
        }

        // Recovery FIRST, and the order is the message rather than an optimization. A standby is a
        // connection pointed at the wrong host; a read-only primary is a setting somebody chose.
        // Reported the other way round, a reader goes looking for a config flag on a machine that is
        // not the one they should be talking to at all.
        if (in_array($this->text($row, 'in_recovery'), ['1', 't', 'true', 'on'], true)) {
            return WriteAcceptance::refused(
                'pg_is_in_recovery()',
                'a standby — this instance replays from a primary and accepts no writes of its own',
            );
        }

        if (in_array($this->text($row, 'read_only'), ['on', 'true', '1'], true)) {
            return WriteAcceptance::refused('default_transaction_read_only', 'a primary configured to refuse writes');
        }

        return WriteAcceptance::accepted();
    }

    /**
     * A column as text, or the empty string when the server did not answer with a scalar.
     *
     * The empty string reads as "not on" everywhere above, and that is the safe direction: a value
     * this build cannot interpret must not become a read-only VERDICT, because a false alarm at a
     * deploy gate is how the gate gets configured away. A genuinely unreadable state throws instead
     * and comes back `undetermined`.
     */
    private function text(object $row, string $key): string
    {
        $value = $row->{$key} ?? null;

        return is_scalar($value) ? (string) $value : '';
    }
}
