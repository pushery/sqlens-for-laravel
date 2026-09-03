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

    public function __construct(private ReaderSession $session) {}

    public function collect(): SettingCrossFacts
    {
        return $this->withTlsOffered(SettingCrossFacts::none());
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
}
