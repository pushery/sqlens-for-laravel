<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Catalog;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Catalog\Setting;
use Pushery\SQLens\Catalog\SettingScope;
use Pushery\SQLens\Catalog\SettingsReading;
use Pushery\SQLens\Contracts\ServerSettingsReader;
use Pushery\SQLens\Findings\UndeterminedReason;
use Throwable;

/**
 * What this PostgreSQL server is configured to do, read from `pg_settings`.
 *
 * One statement over a view, no lock, inside the session the catalog reader already sealed.
 *
 * ## The row that is not there
 *
 * `pg_settings` filters by privilege **silently**: a role without `pg_read_all_settings` does not
 * see a superuser-only row, and the query succeeds with that row simply missing. Measured — no
 * error, no warning, nothing in the result to say a row was withheld.
 *
 * That is why this returns a MAP and never a default. A reader that filled in "the documented
 * default" for a name it did not receive would report a pass about a setting nobody read, and on a
 * managed database — RDS, Cloud SQL, Neon — that is the ordinary case rather than the exotic one. A
 * rule that finds no entry for its name reports that it could not check; a rule handed an invented
 * value reports that everything is fine.
 *
 * ## Why every row is global scope
 *
 * `pg_settings.setting` is the value in effect for THIS session, which for an untouched session is
 * the server's. The reader session does set a few of its own bounds — `statement_timeout`,
 * `lock_timeout`, the read-only seal — so those specific names describe the audit rather than the
 * server, and a rule about them must consult `boot_val`/`reset_val` instead. Every other name is
 * the server's answer, and marking the whole reading global rather than guessing per name keeps
 * that judgment where it belongs: in the rule that knows which names it set.
 */
final readonly class PgsqlServerSettingsReader implements ServerSettingsReader
{
    public function __construct(private ReaderSession $session) {}

    #[RawSql(reason: 'reads pg_settings; a GUC is not a column and the source of each value is part of the answer')]
    public function read(): SettingsReading
    {
        try {
            // One extra round trip, once per reading, for the answer to "why is a name missing?".
            // Without it a consumer finding no entry cannot tell a setting this server does not
            // have from one it was not allowed to see — and only the second is fixable.
            $privilege = $this->session->read(static fn (Connection $db): mixed => $db->selectOne(
                "select pg_has_role(current_user, 'pg_read_all_settings', 'member') as ok"
            ));
            $sawEverything = is_object($privilege) && ($privilege->ok ?? false) === true;

            /** @var array<int, object> $rows */
            $rows = $this->session->read(static fn (Connection $db): array => $db->select(
                'select name, setting, unit, source, sourcefile, context, pending_restart, boot_val, reset_val'
                .' from pg_settings order by name'
            ));
        } catch (Throwable $exception) {
            // Not an exception — the run can still audit a schema — but not a bare empty map
            // either: a named failure is what lets a report say the read never happened rather
            // than implying the server had nothing to report.
            return SettingsReading::failed(UndeterminedReason::CatalogReadFailed, $exception->getMessage());
        }

        $settings = [];

        foreach ($rows as $row) {
            // No guard on the name: `pg_settings.name` is the view's key and is never null or
            // empty, so a skip branch here would be a statement nothing executes. The cast is what
            // keeps the type honest if a driver ever answered otherwise.
            $name = $this->text($row, 'name');

            $settings[$name] = Setting::of(
                $name,
                $this->text($row, 'setting'),
                SettingScope::Global,
                $this->text($row, 'source') === '' ? null : $this->text($row, 'source'),
                // PostgreSQL answers this per setting, so it is a real three-valued fact here
                // rather than the "engine does not report it" null MySQL gives.
                (bool) ($row->pending_restart ?? false),
                // The baseline a rule needs to tell the SERVER's value from the one this reading
                // session installed for itself.
                $this->nullableText($row, 'boot_val'),
                $this->nullableText($row, 'reset_val'),
                $this->nullableText($row, 'unit'),
                // Superuser-restricted, so null here is ordinary rather than exceptional — on a
                // managed database it is simply not available.
                $this->nullableText($row, 'sourcefile'),
                $this->nullableText($row, 'context'),
                // The server's own value, named as such. `setting` above is what THIS session is
                // running with; `reset_val` is what a fresh session would get, which is the server's
                // configuration for this role and database. A server-baseline rule reads only this.
                $this->nullableText($row, 'reset_val'),
            );
        }

        return SettingsReading::of($settings, $sawEverything);
    }

    /** A scalar column as a string — '' when the driver gave something else, which it does not. */
    private function text(object $row, string $key): string
    {
        return $this->nullableText($row, $key) ?? '';
    }

    /** The same, keeping NULL apart from the empty string — the distinction the whole reader turns on. */
    private function nullableText(object $row, string $key): ?string
    {
        $value = $row->{$key} ?? null;

        return is_scalar($value) ? (string) $value : null;
    }
}
