<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Catalog;

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
 * What this MySQL server is configured to do, read from `performance_schema`.
 *
 * ## Global and session are read SEPARATELY, and that is the whole design
 *
 * On MySQL the distinction is not academic: Laravel sets session variables itself on every
 * connection — `sql_mode` and the timezone among them, from `database.connections.*.strict` and
 * `.timezone`. So the session value of `sql_mode` routinely differs from the server's, and a reader
 * that returned only "the value" would report the framework's own choice back to the project as its
 * server configuration.
 *
 * The map is therefore keyed by name and carries BOTH, in the two fields that mean the same thing on
 * both engines: {@see Setting::$value} is what this connection is running with, and
 * {@see Setting::$serverValue} is what the server is configured to. A server-baseline rule reads the
 * second and never the first.
 *
 * That split is deliberate and was not always right here. An earlier version put the GLOBAL value in
 * `value` on the reasoning that it is "the answer a server-baseline rule asks for" — which was true
 * of MySQL and the exact opposite of PostgreSQL, where `pg_settings.setting` is the session's. Two
 * defensible choices that together made `value` mean opposite things per engine, so a rule reading
 * it would have been right on one and silently wrong on the other. Naming the server's value is what
 * removes that trap; it is not a convention rule authors have to remember.
 *
 * ## When performance_schema is off
 *
 * It can be compiled out or disabled, and on some managed hosts it is. The reading then falls back
 * to `SHOW GLOBAL VARIABLES` / `SHOW SESSION VARIABLES`, which every server answers — and which
 * carries no `VARIABLE_SOURCE`, so those settings arrive with a null source rather than an invented
 * one. A reading that cannot happen at all is a named failure, never an empty map that looks like a
 * server with nothing to report.
 */
final class MysqlServerSettingsReader implements ServerSettingsReader
{
    /** Whether the last reading got its variables from performance_schema rather than from SHOW. */
    private bool $usedPerformanceSchema = true;

    public function __construct(private readonly ReaderSession $session) {}

    public function read(): SettingsReading
    {
        try {
            $global = $this->variables('GLOBAL');
            $session = $this->variables('SESSION');
            // Only when the variables themselves came from performance_schema. Asking
            // variables_info after a SHOW fallback would be asking the very schema that just
            // refused — a guaranteed second failure dressed up as a graceful attempt.
            $sources = $this->usedPerformanceSchema ? $this->sources() : [];
        } catch (Throwable $exception) {
            return SettingsReading::failed(UndeterminedReason::CatalogReadFailed, $exception->getMessage());
        }

        $settings = [];

        foreach ($global as $name => $value) {
            $settings[$name] = Setting::of(
                $name,
                // What THIS connection is running with — the same meaning the field carries on
                // PostgreSQL. A GLOBAL-only variable has no session view, and there the value in
                // effect for the session simply IS the global one, so the fallback states a fact
                // rather than papering over a gap.
                $session[$name] ?? $value,
                SettingScope::Global,
                $sources[$name] ?? null,
                // MySQL has no pending_restart equivalent. Null rather than false: answering false
                // would claim a check nobody performed.
                null,
                // boot_val / reset_val are PostgreSQL detail columns with no MySQL counterpart.
                null,
                null,
                null,
                null,
                null,
                // The server's own configuration, named as such — this is what a server-baseline
                // rule judges. Keeping it apart from the session value above is the whole point:
                // Laravel sets sql_mode and the timezone per connection, so the two routinely
                // differ, and a rule reading the session value would report the framework's choice
                // back to the project as its server configuration.
                $value,
            );
        }

        // Every variable answered, or none did — MySQL withholds nothing per row for an ordinary
        // account, so `sawEverything` is true whenever the read succeeded at all.
        // The degradation is reported, not merely survived: a SHOW fallback carries no
        // VARIABLE_SOURCE, and a rule about provenance has to know the reading could not supply it
        // rather than read a missing source as "nobody configured this".
        return SettingsReading::of($settings, true, $this->usedPerformanceSchema);
    }

    /**
     * One collective query per scope. Never one per variable: that would be an N+1 over a system
     * view, and against a production server it is hundreds of round trips for one answer.
     *
     * @return array<string, string>
     */
    #[RawSql(reason: 'reads server variables; @@-variables are not columns and no builder can name one')]
    private function variables(string $scope): array
    {
        $table = $scope === 'GLOBAL' ? 'global_variables' : 'session_variables';

        try {
            $rows = $this->session->read(static fn (Connection $db): array => $db->select(
                "select VARIABLE_NAME as name, VARIABLE_VALUE as value from performance_schema.{$table}"
            ));
        } catch (Throwable) {
            // performance_schema off or not granted — SHOW answers on every server, so the reading
            // degrades in DETAIL rather than failing. What it loses is the source of each value,
            // which is then reported as absent rather than invented.
            $this->usedPerformanceSchema = false;
            $rows = $this->session->read(static fn (Connection $db): array => $db->select("SHOW {$scope} VARIABLES"));
        }

        $values = [];

        foreach ($rows as $row) {
            $name = $this->text($row, 'name') !== '' ? $this->text($row, 'name') : $this->text($row, 'Variable_name');
            $values[$name] = $this->text($row, 'value') !== '' ? $this->text($row, 'value') : $this->text($row, 'Value');
        }

        unset($values['']);

        return $values;
    }

    /**
     * Where each variable's value came from — a fact only `variables_info` carries.
     *
     * Absent rather than guessed when performance_schema is unavailable: "set in a config file" and
     * "still the compiled-in default" call for different actions, and inventing one would send half
     * the readers to the wrong place.
     *
     * @return array<string, string>
     */
    #[RawSql(reason: 'reads where each variable got its value from -- performance_schema.variables_info, which exists for exactly this question')]
    private function sources(): array
    {
        $rows = $this->session->read(static fn (Connection $db): array => $db->select(
            'select VARIABLE_NAME as name, VARIABLE_SOURCE as source from performance_schema.variables_info'
        ));

        $sources = [];

        foreach ($rows as $row) {
            $name = $this->text($row, 'name');

            if ($name !== '') {
                $sources[$name] = $this->text($row, 'source');
            }
        }

        return $sources;
    }

    private function text(mixed $row, string $key): string
    {
        $value = is_object($row) ? ($row->{$key} ?? null) : null;

        return is_scalar($value) ? (string) $value : '';
    }
}
