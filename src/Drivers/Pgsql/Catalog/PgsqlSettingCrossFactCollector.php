<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Catalog;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Catalog\SettingCrossFacts;
use Pushery\SQLens\Contracts\SettingCrossFactCollector;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Rules\Settings\AbstractServerSettingRule;
use Throwable;

/**
 * What a PostgreSQL server-baseline rule needs BESIDE the setting it judges.
 *
 * The MySQL side has had one of these since the `local_infile` finding needed to know who holds
 * `FILE`. This is the PostgreSQL half, and it starts with one fact because one rule needs one.
 *
 * ## Why `ssl` is read again when the reading already carries it
 *
 * A rule judges ONE subject. `ssl` and `ssl_min_protocol_version` arrive as two separate setting
 * subjects, and a rule reaching across to another subject would be reading a value nothing
 * established was measured in the same breath — the reading is assembled from several statements,
 * and on a pooled connection the halves can describe different backends. That is precisely the trap
 * the pooler rung in {@see AbstractServerSettingRule} exists for.
 *
 * A cross-fact is the sanctioned shape: measured deliberately, attached to the variable it is about,
 * and — the part that matters — carrying its own STATE, so a read that failed is `Unavailable`
 * rather than an absence a rule would read as "TLS is on".
 *
 * ## Primum non nocere
 *
 * One `pg_settings` row, no locks, no writes, inside the read-only session the rest of the audit
 * uses. Nothing here can be observed by the server beyond a catalog select.
 */
final readonly class PgsqlSettingCrossFactCollector implements SettingCrossFactCollector
{
    /**
     * The fact name a rule declares to learn whether this server offers TLS at all.
     *
     * Aliased from the core vocabulary rather than owned here, for the same reason its MySQL
     * neighbor is: the rule that reads it lives in the core namespace, which may not name a driver,
     * so the name itself belongs to the vocabulary both sides already share. Kept as a constant here
     * anyway so the query below reads like the ones that will join it.
     */
    public const string TLS_OFFERED = SettingCrossFacts::TLS_OFFERED;

    /**
     * The session's effective `statement_timeout`, measured beside `lock_timeout`.
     *
     * This name lives HERE rather than in the shared vocabulary, unlike the one above, and the rule
     * in the docblock of {@see SettingCrossFacts::FILE_PRIVILEGE_ACCOUNTS} is what decides it: the
     * rule that reads it is a PostgreSQL rule in this same driver namespace, so the contract has one
     * home and the constant sits with the query that fills it.
     *
     * The pair is a different sentence from either half. `lock_timeout` bounds the wait in the lock
     * QUEUE; `statement_timeout` bounds the run AFTERWARDS. Set the first no smaller than the
     * second and the statement is aborted before the lock wait ever reaches its own limit — the
     * configuration reads like a safety net and is not one, and the failure afterwards looks like a
     * timeout on execution rather than a refused lock.
     */
    public const string STATEMENT_TIMEOUT = 'statement_timeout';

    /**
     * WHICH LAYER set either timeout, for the deploy session that would inherit them.
     *
     * Its own fact rather than packed into the one above, because a fact is a triple whose state
     * says whether it was measured, and two answers sharing one slot would have to be taken apart
     * again by whoever reads them. A reader acting on this finding has to know which layer to
     * change; the numbers alone say only that the pair is wrong.
     *
     * ⚠️ Read from `pg_db_role_setting` rather than from `pg_settings.source`, and the difference is
     * the whole reason this fact exists. `source` describes where the CURRENT SESSION's value came
     * from — and this audit sets both of these timeouts on its own session before it reads anything
     * (`capture.session.lock_timeout`). So `source` here says `session` for both, every time,
     * describing SQLens rather than the server. `pg_db_role_setting` holds what `ALTER DATABASE` and
     * `ALTER ROLE` put there, which is what a deploy actually inherits; a timeout named in neither
     * came from the configuration file or the built-in default.
     */
    public const string TIMEOUT_OVERRIDES = 'timeout_overrides';

    public function __construct(private ReaderSession $session) {}

    public function collect(): SettingCrossFacts
    {
        return $this->withStatementTimeout($this->withTlsOffered(SettingCrossFacts::none()));
    }

    /**
     * Whether `ssl` is on, read beside `ssl_min_protocol_version`.
     *
     * The two together are a different sentence from either alone. A minimum below the floor says an
     * old TLS version can still be negotiated; `ssl = off` says nothing is negotiated at all, and
     * the minimum is then a configured value describing a capability that is not running. Measured
     * on 18.4: with `ssl = off` the minimum still reads `TLSv1.2`, so the value gives no hint of it.
     */
    #[RawSql(reason: 'asks whether the server actually offers TLS, so a setting is judged against what a client could really negotiate')]
    private function withTlsOffered(SettingCrossFacts $facts): SettingCrossFacts
    {
        try {
            $rows = $this->session->read(fn (Connection $db): array => $db->select(
                "select setting from pg_settings where name = 'ssl'",
            ));
        } catch (Throwable $exception) {
            // The arm this fact exists for. `pg_settings` is readable by any role, so a failure here
            // is a refused or dropped connection rather than a permission — either way the consuming
            // rule must report that it could not check, because "no row" and "TLS is on" are the
            // same silence otherwise.
            return $facts->withUnavailable(
                'ssl_min_protocol_version',
                self::TLS_OFFERED,
                UndeterminedReason::CatalogReadFailed,
                $exception->getMessage(),
            );
        }

        $row = $rows[0] ?? null;
        $value = is_object($row) ? ($row->setting ?? null) : null;

        if (! is_scalar($value)) {
            // A server that does not carry the parameter at all — every supported version does, so
            // this is a reading that went wrong rather than an older PostgreSQL. Unavailable, not an
            // invented `off`: guessing here would turn an unreadable catalog into a finding about
            // the server's configuration.
            return $facts->withUnavailable(
                'ssl_min_protocol_version',
                self::TLS_OFFERED,
                UndeterminedReason::CatalogReadFailed,
                'pg_settings returned no row for ssl',
            );
        }

        return $facts->withMeasured('ssl_min_protocol_version', self::TLS_OFFERED, (string) $value);
    }

    /**
     * What `statement_timeout` a fresh session on this server would start with, read beside
     * `lock_timeout`.
     *
     * Read as its own measurement rather than taken off the reading a rule already holds, for the
     * reason the class docblock gives for `ssl`: a rule judges ONE subject, and reaching across to
     * another one would use a value nothing established was measured in the same breath. On a
     * pooled connection the two halves can describe different backends, and the whole point of this
     * pair is that the two numbers are compared against each other.
     *
     * ⚠️ `reset_val`, NOT `setting`, and getting this wrong would make the rule judge SQLens. The
     * audit sets its own `lock_timeout` and `statement_timeout` before it reads anything, so
     * `setting` describes this tool's preamble on every server it is ever pointed at. `reset_val` is
     * what a `RESET` returns to: the value the server file, the database and the role have settled
     * between them, which is exactly what a deploy session inherits before it sets anything itself.
     */
    #[RawSql(reason: 'reads the reset value of statement_timeout so lock_timeout is judged against the clock a fresh deploy session would inherit, not against the audit session own preamble')]
    private function withStatementTimeout(SettingCrossFacts $facts): SettingCrossFacts
    {
        try {
            $rows = $this->session->read(fn (Connection $db): array => $db->select(
                "select reset_val from pg_settings where name = 'statement_timeout'",
            ));
        } catch (Throwable $exception) {
            return $facts->withUnavailable(
                'lock_timeout',
                self::STATEMENT_TIMEOUT,
                UndeterminedReason::CatalogReadFailed,
                $exception->getMessage(),
            );
        }

        $row = $rows[0] ?? null;
        $value = is_object($row) ? ($row->reset_val ?? null) : null;

        if (! is_scalar($value)) {
            // Unavailable rather than an invented zero. A zero here would be read by the rule as
            // "no statement clock", which is the state in which it reports nothing — so a failed
            // read would silence the rule while looking exactly like a clean pass.
            return $facts->withUnavailable(
                'lock_timeout',
                self::STATEMENT_TIMEOUT,
                UndeterminedReason::CatalogReadFailed,
                'pg_settings returned no reset_val for statement_timeout',
            );
        }

        return $this->withTimeoutOverrides(
            $facts->withMeasured('lock_timeout', self::STATEMENT_TIMEOUT, (string) $value),
        );
    }

    /**
     * Which layer named either timeout for the session a deploy would run in.
     *
     * Answers the question the numbers cannot: a reader told the pair is ineffective still has to
     * know WHERE to change it, and `ALTER DATABASE`, `ALTER ROLE` and `postgresql.conf` are three
     * different files on three different change paths.
     *
     * `pg_db_role_setting` is the only place the first two are visible, and its rows are keyed by
     * database oid and role oid with `0` meaning "all". Scoped to THIS database and the CURRENT
     * role, because a setting on some other role is not what this deploy will inherit.
     *
     * Measured-empty is a real answer and says the pair came from the configuration file or the
     * built-in default, so it is written as an empty string rather than left off — an absent fact
     * reads as `Unavailable`, which would make the rule report that it could not check.
     */
    #[RawSql(reason: 'reads pg_db_role_setting; per-database and per-role overrides are not visible anywhere else, and pg_settings.source describes this session rather than a deploy')]
    private function withTimeoutOverrides(SettingCrossFacts $facts): SettingCrossFacts
    {
        try {
            $rows = $this->session->read(fn (Connection $db): array => $db->select(
                'select s.setconfig,'
                .' case when s.setdatabase = 0 then \'role\''
                .'      when s.setrole = 0 then \'database\''
                .'      else \'role_in_database\' end as scope'
                .' from pg_db_role_setting s'
                .' where (s.setdatabase = 0 or s.setdatabase = (select oid from pg_database where datname = pg_catalog.current_database()))'
                .' and (s.setrole = 0 or s.setrole = (select oid from pg_roles where rolname = current_user))',
            ));
        } catch (Throwable $exception) {
            return $facts->withUnavailable(
                'lock_timeout',
                self::TIMEOUT_OVERRIDES,
                UndeterminedReason::CatalogReadFailed,
                $exception->getMessage(),
            );
        }

        $found = [];

        foreach ($rows as $row) {
            $config = is_object($row) ? ($row->setconfig ?? null) : null;
            $scope = is_object($row) ? ($row->scope ?? null) : null;

            if (! is_string($config) || ! is_string($scope)) {
                continue;
            }

            foreach (['statement_timeout', 'lock_timeout'] as $name) {
                if (str_contains($config, $name.'=')) {
                    $found[$name.':'.$scope] = true;
                }
            }
        }

        $names = array_keys($found);
        sort($names);

        return $facts->withMeasured('lock_timeout', self::TIMEOUT_OVERRIDES, implode(',', $names));
    }
}
