<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Catalog;

use DateTimeImmutable;
use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Catalog\Degradation\DatabaseErrorTranslator;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Catalog\SkipReason;
use Pushery\SQLens\Catalog\Statistics\Estimate;
use Pushery\SQLens\Catalog\Statistics\EstimateSource;
use Pushery\SQLens\Catalog\Statistics\IndexStatistics;
use Pushery\SQLens\Catalog\Statistics\StatisticsRequest;
use Pushery\SQLens\Catalog\Statistics\StatisticsSnapshot;
use Pushery\SQLens\Catalog\Statistics\StorageHeadroom;
use Pushery\SQLens\Catalog\Statistics\TableStatistics;
use Pushery\SQLens\Contracts\StatisticsReader;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Throwable;

/**
 * What this MySQL server will say about how big things are.
 *
 * The sibling of the PostgreSQL reader, and deliberately NOT a translation of it: the two engines
 * answer differently enough that copying the shape would have produced wrong numbers dressed in the
 * right types.
 *
 * ## Nothing here is exact, and that is the engine talking
 *
 * Every number this reader produces is an estimate. `TABLE_ROWS` is a sampled figure that MySQL
 * documents as varying from the truth by as much as forty to fifty percent for InnoDB, and
 * `DATA_LENGTH` is pages allocated multiplied by page size — an approximation of ALLOCATION rather
 * than a measurement of content, so a table just emptied still reports the pages it holds.
 *
 * This reader therefore never calls `Estimate::exact()`, while the PostgreSQL one calls it for
 * every byte count. That asymmetry is real, it is the engines' and not this package's, and it is
 * the reason precision belongs to the driver that read the number rather than to the quantity.
 *
 * ## The expensive-query trap is avoided by leaving a setting alone
 *
 * Measured on 8.4.10: `information_schema_stats_expiry` is `86400`, so a query against
 * `information_schema.TABLES` is served from cached statistics — the cheap path, and the default.
 * Setting it to `0` forces a fresh read of every table's statistics, which is exactly the expensive
 * behavior a gate must not trigger immediately before a deploy. So it is not set here, and no
 * `ANALYZE TABLE` is ever sent.
 *
 * ## `DATA_FREE` is not free space, and using it as such would be the worst kind of wrong
 *
 * It is reclaimable room INSIDE a tablespace file — fragmentation, not capacity. A headroom reading
 * built on it would tell a deploy gate "there is room for the rewrite" on the strength of gaps in a
 * file that cannot hold a second copy of the table. MySQL has no more SQL for the volume's free
 * space than PostgreSQL does, so the same named skip is reported, for the same reason.
 */
final readonly class MysqlStatisticsReader implements StatisticsReader
{
    public function __construct(private ReaderSession $session) {}

    #[RawSql(reason: 'reads table and index statistics from information_schema; those tables are not models and the aggregate a size picture needs has no builder form')]
    public function read(StatisticsRequest $request): StatisticsSnapshot
    {
        /** @var list<CatalogSkip> $skips */
        $skips = [];

        // The request's own budget, applied rather than merely carried. It only ever tightens: the
        // audit budget is the operator's statement about what this package may cost their server,
        // and a number arriving with a request must not be able to widen it.
        $session = $this->session->withBudget($this->session->budget()->narrowedTo($request->budgetMilliseconds));

        // Resolved ONCE, and only when the request did not state it. MySQL's "schema" is a database,
        // so a bare `orders` means the table in the database this connection is pointed at — and
        // asking the server per object would be one round trip per table to answer one question.
        $defaultSchema = $request->schemas[0] ?? $this->currentDatabase($session, $skips);
        $bindings = $this->bindings($request, $defaultSchema);

        $rows = DatabaseErrorTranslator::attemptBounded(
            fn (): array => array_values($session->read(
                fn (Connection $db): array => $db->select($this->tableQuery($request), $bindings),
            )),
            SchemaObjectType::Table,
            'table statistics',
            $session,
            $skips,
        );

        // A SEPARATE read, and a separately skippable one. The freshness and the per-index sizes
        // live in the `mysql` schema, which an ordinary application role commonly may not read —
        // and losing the row counts because the timestamp beside them was withheld would discard
        // the useful half to record that the other half was unavailable.
        $freshness = DatabaseErrorTranslator::attemptBounded(
            fn (): array => array_values($session->read(
                fn (Connection $db): array => $db->select($this->freshnessQuery($request), $bindings),
            )),
            SchemaObjectType::Table,
            'statistics freshness',
            $session,
            $skips,
        );

        $indexRows = DatabaseErrorTranslator::attemptBounded(
            fn (): array => array_values($session->read(
                fn (Connection $db): array => $db->select($this->indexQuery($request), $bindings),
            )),
            SchemaObjectType::Index,
            'index statistics',
            $session,
            $skips,
        );

        $tables = $this->tablesFrom($request, $defaultSchema, $rows, $this->freshnessBy($freshness), $indexRows);

        return new StatisticsSnapshot($request, $tables, $this->headroom($defaultSchema, $session, $skips), $skips);
    }

    /**
     * Table-level numbers, from the cached statistics.
     *
     * `TABLE_SCHEMA` is compared against the requested schema where the caller gave one and against
     * the connection's own database otherwise, which is what makes a bare `orders` mean the table in
     * the database this connection is pointed at rather than the first `orders` on the server.
     */
    private function tableQuery(StatisticsRequest $request): string
    {
        $placeholders = implode(', ', array_fill(0, count($request->objects), '?'));

        return <<<SQL
            select TABLE_SCHEMA as schema_name,
                   TABLE_NAME as table_name,
                   TABLE_ROWS as row_estimate,
                   DATA_LENGTH as table_bytes,
                   INDEX_LENGTH as index_bytes,
                   coalesce(DATA_LENGTH, 0) + coalesce(INDEX_LENGTH, 0) as total_bytes
              from information_schema.TABLES
             where TABLE_TYPE = 'BASE TABLE'
               and concat(TABLE_SCHEMA, '.', TABLE_NAME) in ({$placeholders})
            SQL;
    }

    /**
     * When InnoDB last refreshed the statistics behind those numbers.
     *
     * `mysql.innodb_table_stats.last_update` is the only place MySQL states this, and it is the
     * reason the freshness is a second query rather than a join: a role that may read
     * `information_schema` may well not read the `mysql` schema, and the two answers have to be
     * able to arrive separately.
     */
    private function freshnessQuery(StatisticsRequest $request): string
    {
        $placeholders = implode(', ', array_fill(0, count($request->objects), '?'));

        return <<<SQL
            select concat(database_name, '.', table_name) as object_name,
                   last_update
              from mysql.innodb_table_stats
             where concat(database_name, '.', table_name) in ({$placeholders})
            SQL;
    }

    /**
     * Per-index sizes, converted from pages to bytes in the server.
     *
     * `innodb_index_stats` reports `size` in PAGES — measured: a 500-row table's primary key comes
     * back as `1`. Reporting that as a byte count would understate every index by four orders of
     * magnitude, which is the kind of wrong that looks like a small table rather than like a bug.
     */
    private function indexQuery(StatisticsRequest $request): string
    {
        $placeholders = implode(', ', array_fill(0, count($request->objects), '?'));

        return <<<SQL
            select concat(database_name, '.', table_name) as object_name,
                   index_name,
                   stat_value * @@innodb_page_size as index_bytes
              from mysql.innodb_index_stats
             where stat_name = 'size'
               and concat(database_name, '.', table_name) in ({$placeholders})
            SQL;
    }

    /**
     * The requested names with the table prefix put back on, qualified against this database.
     *
     * @return list<string>
     */
    private function bindings(StatisticsRequest $request, string $defaultSchema): array
    {
        return array_map(
            fn (string $object): string => $this->serverName($object, $request->tablePrefix, $defaultSchema),
            $request->objects,
        );
    }

    private function serverName(string $object, string $prefix, string $defaultSchema): string
    {
        $dot = strrpos($object, '.');

        $schema = $dot === false ? $defaultSchema : substr($object, 0, $dot);
        $table = $dot === false ? $object : substr($object, $dot + 1);

        return $schema.'.'.$prefix.$table;
    }

    /**
     * The database this connection is pointed at, or the empty string with a named skip.
     *
     * Asked rather than taken from configuration, because the configuration says which database the
     * connection was OPENED against and a `USE` since then would have moved it — and a reading
     * scoped to the wrong database answers about tables nobody asked about while reporting the ones
     * they did ask about as missing.
     *
     * @param  list<CatalogSkip>  $skips
     */
    #[RawSql(reason: 'asks database() -- a server function naming the schema this session is in')]
    private function currentDatabase(ReaderSession $session, array &$skips): string
    {
        try {
            $rows = array_values($session->read(static fn (Connection $db): array => $db->select('select database() as name')));
        } catch (Throwable $error) {
            $skips[] = DatabaseErrorTranslator::skipFor(SchemaObjectType::Database, 'current database', $error);

            return '';
        }

        $row = $rows[0] ?? null;

        return is_object($row) ? $this->text($row, 'name') : '';
    }

    /**
     * @param  list<mixed>  $rows
     * @param  array<string, DateTimeImmutable>  $freshness
     * @param  list<mixed>  $indexRows
     * @return list<TableStatistics>
     */
    private function tablesFrom(StatisticsRequest $request, string $defaultSchema, array $rows, array $freshness, array $indexRows): array
    {
        $tables = [];

        foreach ($rows as $row) {
            if (! is_object($row)) {
                continue;
            }

            $serverName = $this->text($row, 'schema_name').'.'.$this->text($row, 'table_name');
            $requested = $this->requestedNameFor($request, $defaultSchema, $serverName);

            if ($requested === null) {
                continue;
            }

            $refreshedAt = $freshness[$serverName] ?? null;

            $tables[] = new TableStatistics(
                $requested,
                $this->estimate($row, 'row_estimate', EstimateSource::RowCount, $refreshedAt),
                $this->estimate($row, 'table_bytes', EstimateSource::TableBytes, $refreshedAt),
                $this->estimate($row, 'index_bytes', EstimateSource::IndexBytes, $refreshedAt),
                $this->estimate($row, 'total_bytes', EstimateSource::TotalBytes, $refreshedAt),
                $this->indexesOf($serverName, $requested, $indexRows, $refreshedAt),
            );
        }

        return $tables;
    }

    private function requestedNameFor(StatisticsRequest $request, string $defaultSchema, string $serverName): ?string
    {
        foreach ($request->objects as $object) {
            if ($this->serverName($object, $request->tablePrefix, $defaultSchema) === $serverName) {
                return $object;
            }
        }

        return null;
    }

    /**
     * A number from this engine — always an estimate, with whatever freshness could be established.
     *
     * There is no `exact()` branch here and there must not be one. Every number MySQL reports about
     * a table's size or population comes out of stored statistics, so a value built as exact would
     * be a claim the engine never made.
     */
    private function estimate(object $row, string $key, EstimateSource $source, ?DateTimeImmutable $refreshedAt): ?Estimate
    {
        $value = $this->number($row, $key);

        if ($value === null || $value < 0) {
            return null;
        }

        return $refreshedAt instanceof DateTimeImmutable
            ? Estimate::measured((int) $value, $source, $refreshedAt)
            // Not `neverCollected`: that would report the SERVER as saying no statistics exist,
            // which is a claim nobody measured. The freshness could not be read, and that is a
            // different fact with a different fix — a privilege rather than an ANALYZE.
            : Estimate::freshnessUnknown((int) $value, $source);
    }

    /**
     * @param  list<mixed>  $rows
     * @return array<string, DateTimeImmutable>
     */
    private function freshnessBy(array $rows): array
    {
        $byObject = [];

        foreach ($rows as $row) {
            if (! is_object($row)) {
                continue;
            }

            $stamp = $this->text($row, 'last_update');
            $object = $this->text($row, 'object_name');
            if ($stamp === '') {
                continue;
            }
            if ($object === '') {
                continue;
            }

            try {
                $byObject[$object] = new DateTimeImmutable($stamp);
            } catch (Throwable) {
                // A stamp this package cannot parse costs the freshness, never the number that came
                // with it: the row count is still the row count.
                continue;
            }
        }

        return $byObject;
    }

    /**
     * @param  list<mixed>  $indexRows
     * @return list<IndexStatistics>
     */
    private function indexesOf(string $serverName, string $requested, array $indexRows, ?DateTimeImmutable $refreshedAt): array
    {
        $indexes = [];
        $dot = strrpos($requested, '.');
        $prefix = $dot === false ? '' : substr($requested, 0, $dot + 1);

        foreach ($indexRows as $row) {
            if (! is_object($row)) {
                continue;
            }

            if ($this->text($row, 'object_name') !== $serverName) {
                continue;
            }

            $indexes[] = new IndexStatistics(
                $prefix.$this->text($row, 'index_name'),
                $this->estimate($row, 'index_bytes', EstimateSource::IndexBytes, $refreshedAt),
            );
        }

        return $indexes;
    }

    /**
     * The capacity picture: how much this database occupies, and a named absence for what is left.
     *
     * Summed from the same cached statistics the tables came from, so it is an estimate like
     * everything else here — PostgreSQL answers this one exactly, and the difference travels on the
     * number rather than in a footnote.
     *
     * `DATA_FREE` is deliberately not offered as the free half. It is reclaimable room inside a
     * tablespace file rather than capacity on the volume, and a gate told "there is room" on the
     * strength of fragmentation would wave through the rewrite that fills the disk.
     *
     * @param  list<CatalogSkip>  $skips
     * @return list<StorageHeadroom>
     */
    #[RawSql(reason: 'reads the auto-increment ceiling against the column type; the answer lives in information_schema and nowhere a model could reach')]
    private function headroom(string $schema, ReaderSession $session, array &$skips): array
    {
        if ($schema === '') {
            return [];
        }

        try {
            $rows = array_values($session->read(static fn (Connection $db): array => $db->select(
                'select coalesce(sum(coalesce(DATA_LENGTH, 0) + coalesce(INDEX_LENGTH, 0)), 0) as used_bytes'
                ." from information_schema.TABLES where TABLE_SCHEMA = ? and TABLE_TYPE = 'BASE TABLE'",
                [$schema],
            )));
        } catch (Throwable $error) {
            $skips[] = DatabaseErrorTranslator::skipFor(SchemaObjectType::Database, 'database size', $error);

            return [];
        }

        $row = $rows[0] ?? null;

        if (! is_object($row)) {
            return [];
        }

        $used = $this->number($row, 'used_bytes');

        if ($used === null) {
            return [];
        }

        return [StorageHeadroom::sizeOnly(
            $schema,
            Estimate::freshnessUnknown((int) $used, EstimateSource::StorageUsedBytes),
            CatalogSkip::for(
                SchemaObjectType::Database,
                $schema,
                SkipReason::NotReadable,
                'MySQL reports no free space for the volume its data directory sits on — DATA_FREE is '
                .'reclaimable room inside a tablespace file, not capacity, and reading it as capacity '
                .'would wave through the rewrite that fills the disk',
            ),
        )];
    }

    /** A column read as text, or the empty string when the server did not answer with a scalar. */
    private function text(object $row, string $key): string
    {
        $value = $row->{$key} ?? null;

        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * A column read as a number, or null when the server answered with nothing usable.
     *
     * Null rather than zero. `TABLE_ROWS` is NULL for a table InnoDB has no statistics for, and a
     * zero there would report an unmeasured table as an empty one.
     */
    private function number(object $row, string $key): ?float
    {
        $value = $row->{$key} ?? null;

        return is_numeric($value) ? (float) $value : null;
    }
}
