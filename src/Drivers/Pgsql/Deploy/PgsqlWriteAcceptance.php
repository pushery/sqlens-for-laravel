<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Deploy;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Contracts\ReadsWriteAcceptance;
use Pushery\SQLens\Deploy\Checks\PreflightStateUnreadable;
use Pushery\SQLens\Deploy\WriteAcceptance;
use Pushery\SQLens\Drivers\Pgsql\Catalog\PgsqlRoleDefaultsReader;
use Pushery\SQLens\Drivers\Pgsql\Catalog\RoleDefaults;

/**
 * PostgreSQL's answer to "will this instance accept writes".
 *
 * Moved here from `ReadOnlyTargetCheck`, which asked it behind a `$context->driver === 'mysql'`
 * branch — a driver decision inside the core. The queries and the ordering are the
 * ones that were already there; what changed is who knows them.
 *
 * ## `default_transaction_read_only` is judged for the role the migrations run as
 *
 * The setting can be stored per role and per database with `ALTER ROLE … SET` and
 * `ALTER DATABASE … SET`, and `current_setting()` answers for the role that reads it. A preflight
 * reads through an account of its own, and an operator who hardens that account with
 * `default_transaction_read_only = on` has done the right thing. Read as the instance's state, it
 * stopped every deploy on a writable primary, while a migration role that really starts read-only
 * passed. So the value is resolved as a fresh session of the migration role gets it: the role's own
 * default for this database, then for every database, then the default of this database or of every
 * role, then the server's value, the same order `ServerSettingsCheck` reads `lock_timeout` in. Where
 * the rows cannot tell, the answer is that it cannot, never the reading role's value.
 */
final readonly class PgsqlWriteAcceptance implements ReadsWriteAcceptance
{
    private const string SETTING = 'default_transaction_read_only';

    #[RawSql(reason: 'reads pg_catalog.pg_is_in_recovery() and default_transaction_read_only -- a server function and a GUC, neither of which has a builder expression')]
    public function writeAcceptance(ReaderSession $session, ?string $migrationRole = null): WriteAcceptance
    {
        $row = $session->read(static fn (Connection $db): array => $db->select(
            'select pg_catalog.pg_is_in_recovery() as in_recovery,'
            .' pg_catalog.current_setting(\'default_transaction_read_only\') as read_only',
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
                'pg_catalog.pg_is_in_recovery()',
                'a standby — this instance replays from a primary and accepts no writes of its own',
            );
        }

        $start = $this->migrationStart($this->text($row, 'read_only'), new PgsqlRoleDefaultsReader($session)->read(), $migrationRole);

        if (! $start['readOnly']) {
            return WriteAcceptance::accepted();
        }

        return $start['ownedBy'] === null
            ? WriteAcceptance::refused(self::SETTING, 'a primary configured to refuse writes')
            : WriteAcceptance::refused(self::SETTING, sprintf('a primary on which `%s`, the role the migrations run as, starts every transaction read-only', $start['ownedBy']));
    }

    /**
     * Whether a fresh session of the role the migrations run as starts read-only, and the role whose
     * own default decided it, or null when a database, every role or the server decided.
     *
     * @return array{readOnly: bool, ownedBy: ?string}
     *
     * @throws PreflightStateUnreadable when the stored defaults cannot say which value that session gets
     */
    private function migrationStart(string $readerValue, RoleDefaults $defaults, ?string $role): array
    {
        if (! $defaults->read) {
            throw new PreflightStateUnreadable('the defaults stored per role and database could not be read, so '
                .'whether the role the migrations run as starts read-only is unknown');
        }

        $owners = $defaults->rolesWithOwn(self::SETTING);

        if ($role === null && $owners !== []) {
            throw new PreflightStateUnreadable(sprintf(
                'the role the migrations run as is not configured, and %s %s, so whether the migrations '
                .'start read-only is unknown',
                implode(', ', array_map(static fn (string $owner): string => '`'.$owner.'`', $owners)),
                count($owners) === 1 ? 'carries a `default_transaction_read_only` default of its own' : 'carry `default_transaction_read_only` defaults of their own',
            ));
        }

        $own = $role === null ? null : $defaults->own($role, self::SETTING);
        $stored = $own ?? $defaults->shared(self::SETTING);

        if ($stored === null && in_array($defaults->reader, $owners, true)) {
            throw new PreflightStateUnreadable(sprintf(
                '`%s`, the role this check reads as, carries a `default_transaction_read_only` default of '
                .'its own, which hides the server\'s value, and `%s`, the role the migrations run as, has none',
                $defaults->reader,
                (string) $role,
            ));
        }

        if ($stored === null) {
            // The session's own value, which `current_setting()` gives as `on` or `off`. One this build
            // cannot read is not a verdict, as text() says.
            return ['readOnly' => $this->boolean($readerValue) ?? false, 'ownedBy' => null];
        }

        $readOnly = $this->boolean($stored)
            ?? throw new PreflightStateUnreadable(sprintf('the stored default `default_transaction_read_only = %s` is not a value this check can read', $stored));

        return ['readOnly' => $readOnly, 'ownedBy' => $own === null ? null : $role];
    }

    /**
     * A boolean setting the way PostgreSQL reads one, or null for a spelling it would not accept.
     *
     * `current_setting()` answers `on` or `off`; a stored default keeps the spelling it was written
     * with, so `true`, `yes` and `1` arrive as well.
     */
    private function boolean(string $value): ?bool
    {
        return match (strtolower(trim($value))) {
            'on', 'true', 'yes', '1', 't', 'y' => true,
            'off', 'false', 'no', '0', 'f', 'n' => false,
            default => null,
        };
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
