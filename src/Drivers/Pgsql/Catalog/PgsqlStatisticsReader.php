<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Catalog;

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
 * What this PostgreSQL server will say about how big things are.
 *
 * Three statements over catalog and statistics views, no lock, inside the session the reader layer
 * already sealed read-only. Nothing here touches a user table: a row count comes from what the
 * planner remembers, never from counting.
 *
 * ## Partitioned tables answer two different ways, and one of them is a trap
 *
 * Measured on PostgreSQL 18, on a parent with two partitions holding 500 and 300 rows:
 *
 * | | reltuples | pg_relation_size | pg_indexes_size | pg_total_relation_size |
 * |---|---|---|---|---|
 * | the partitioned parent | **800** | **0** | **0** | **0** |
 * | one partition | 500 | 24576 | 32768 | 81920 |
 *
 * The row count on the parent is already the whole tree — ANALYZE collects inheritance statistics
 * into it — so summing the partitions on top would report 1600 rows for 800. The SIZES are not: a
 * partitioned parent has no storage of its own, so all three functions answer zero.
 *
 * Zero is the trap. It is not "unknown"; it is a number, and it reads as "this table is tiny" —
 * about the one kind of table where a migration hurts most. So the sizes are summed across
 * `pg_partition_tree()` and the row count is taken as it stands, which is the opposite treatment
 * for the two halves of the same row and exactly why this is measured rather than assumed.
 *
 * ## A never-analyzed table has no row count, and says so
 *
 * Since PostgreSQL 14 `reltuples` is `-1` for a relation nobody has vacuumed or analyzed, precisely
 * so "no statistics" cannot pass for "no rows". That sentinel is resolved here and never forwarded:
 * the table comes back with no row count and a named skip, because a report saying "-1 rows" is
 * worse than one that says the number is missing.
 *
 * ## Free space is a skip, not a number
 *
 * PostgreSQL will say how much room a database occupies and will not say how much is left on the
 * volume underneath it — there is no SQL for it. Guessing would be the worst available answer, so
 * the headroom reading carries a named skip and the snapshot goes partial. The escalation that
 * consumes this has to see the absence rather than a quiet zero.
 */
final readonly class PgsqlStatisticsReader implements StatisticsReader
{
    public function __construct(private ReaderSession $session) {}

    #[RawSql(reason: 'reads pg_class and pg_stat_user_tables; the statistics catalog is not a model and the aggregate has no builder form')]
    public function read(StatisticsRequest $request): StatisticsSnapshot
    {
        /** @var list<CatalogSkip> $skips */
        $skips = [];

        // The request's own budget, applied rather than merely carried. It only ever tightens: the
        // audit budget is the operator's statement about what this package may cost their server,
        // and a number arriving with a request must not be able to widen it.
        $session = $this->session->withBudget($this->session->budget()->narrowedTo($request->budgetMilliseconds));

        $rows = DatabaseErrorTranslator::attemptBounded(
            fn (): array => array_values($session->read(
                fn (Connection $db): array => $db->select($this->tableQuery($request), $this->tableBindings($request)),
            )),
            SchemaObjectType::Table,
            'table statistics',
            $session,
            $skips,
        );

        $indexRows = DatabaseErrorTranslator::attemptBounded(
            fn (): array => array_values($session->read(
                fn (Connection $db): array => $db->select($this->indexQuery($request), $this->tableBindings($request)),
            )),
            SchemaObjectType::Index,
            'index statistics',
            $session,
            $skips,
        );

        $tables = $this->tablesFrom($request, $rows, $indexRows, $skips);

        return new StatisticsSnapshot($request, $tables, $this->headroom($session, $skips), $skips);
    }

    /**
     * Table-level numbers for the requested objects, in one round trip.
     *
     * The `case` on `relkind` is the partition handling described on the class, and it is written
     * into the SQL rather than resolved with a second query on purpose: a partitioned parent would
     * otherwise need a follow-up per table, and the extra round trips land on a production server
     * at the worst possible moment.
     */
    private function tableQuery(StatisticsRequest $request): string
    {
        $placeholders = implode(', ', array_fill(0, count($request->objects), '?'));

        return <<<SQL
            select n.nspname as schema_name,
                   c.relname as table_name,
                   c.relkind::text as kind,
                   c.reltuples::float8 as row_estimate,
                   case when c.relkind = 'p'
                        then (select coalesce(sum(pg_relation_size(t.relid)), 0) from pg_partition_tree(c.oid) t)
                        else pg_relation_size(c.oid) end as table_bytes,
                   case when c.relkind = 'p'
                        then (select coalesce(sum(pg_indexes_size(t.relid)), 0) from pg_partition_tree(c.oid) t)
                        else pg_indexes_size(c.oid) end as index_bytes,
                   case when c.relkind = 'p'
                        then (select coalesce(sum(pg_total_relation_size(t.relid)), 0) from pg_partition_tree(c.oid) t)
                        else pg_total_relation_size(c.oid) end as total_bytes,
                   s.last_analyze,
                   s.last_autoanalyze
              from pg_class c
              join pg_namespace n on n.oid = c.relnamespace
              left join pg_stat_all_tables s on s.relid = c.oid
             where c.relkind in ('r', 'p', 'm')
               and (
                     n.nspname || '.' || c.relname in ({$placeholders})
                  or (c.relname in ({$placeholders}) and pg_table_is_visible(c.oid))
                   )
            SQL;
    }

    /**
     * Per-index sizes for the same objects.
     *
     * `relispartition = false` keeps this to the indexes somebody declared: a partitioned index's
     * own partitions are indexes too, and listing them would report one index n times under names
     * nobody wrote. Their storage is not lost — the same `pg_partition_tree()` sum picks it up.
     */
    private function indexQuery(StatisticsRequest $request): string
    {
        $placeholders = implode(', ', array_fill(0, count($request->objects), '?'));

        return <<<SQL
            select n.nspname as schema_name,
                   c.relname as table_name,
                   i.relname as index_name,
                   case when i.relkind = 'I'
                        then (select coalesce(sum(pg_relation_size(t.relid)), 0) from pg_partition_tree(i.oid) t)
                        else pg_relation_size(i.oid) end as index_bytes
              from pg_index x
              join pg_class i on i.oid = x.indexrelid
              join pg_class c on c.oid = x.indrelid
              join pg_namespace n on n.oid = c.relnamespace
             where i.relispartition = false
               and (
                     n.nspname || '.' || c.relname in ({$placeholders})
                  or (c.relname in ({$placeholders}) and pg_table_is_visible(c.oid))
                   )
            SQL;
    }

    /**
     * The requested names, with the table prefix put BACK on.
     *
     * The request speaks in the names a project believes it has — a prefix is stripped when objects
     * are named — so the server has to be asked about `acme_orders` for a request that said
     * `orders`. Everything comes back under the requested spelling, which is what lets the snapshot's
     * own accessors line up with what the caller asked.
     *
     *
     * The requested objects, offered to BOTH comparisons the queries make.
     *
     * A migration says `orders`; the catalog holds `public.orders`. Matching only the composed name
     * meant a finding about an unqualified statement — which is almost every Laravel migration —
     * found no statistics at all, so nothing was ever weighed and nothing turned red. The same
     * defect was already fixed once in {@see PgsqlActivityReader}, and this is the same correction:
     * every object is offered to both arms rather than classified first, because the two cannot
     * collide (a qualified `public.orders` never equals a bare `relname`, and a bare `orders` never
     * equals the composed name), so nothing has to guess which form it was handed and a table whose
     * name contains a literal dot stays safe.
     *
     * `pg_table_is_visible()` is what makes the bare arm honest: it asks the SERVER whether an
     * unqualified reference would find this table — `search_path` resolved by the thing that owns
     * it. `search_path` is a LIST, so appending a guessed `public.` would have been the wrong answer
     * on any project that sets one.
     *
     * @return list<string>
     * @return list<string>
     */
    private function tableBindings(StatisticsRequest $request): array
    {
        $names = array_map(
            fn (string $object): string => $this->serverName($object, $request->tablePrefix),
            $request->objects,
        );

        // Bound TWICE, once per comparison, in the order the two appear in the SQL.
        return [...$names, ...$names];
    }

    private function serverName(string $object, string $prefix): string
    {
        if ($prefix === '') {
            return $object;
        }

        $dot = strrpos($object, '.');

        return $dot === false
            ? $prefix.$object
            : substr($object, 0, $dot + 1).$prefix.substr($object, $dot + 1);
    }

    /**
     * @param  list<mixed>  $rows
     * @param  list<mixed>  $indexRows
     * @param  list<CatalogSkip>  $skips
     * @return list<TableStatistics>
     */
    private function tablesFrom(StatisticsRequest $request, array $rows, array $indexRows, array &$skips): array
    {
        $tables = [];

        foreach ($rows as $row) {
            if (! is_object($row)) {
                continue;
            }

            $bareName = $this->text($row, 'table_name');
            $serverName = $this->text($row, 'schema_name').'.'.$bareName;
            $requested = $this->requestedNameFor($request, $serverName, $bareName);

            if ($requested === null) {
                continue;
            }

            $analyzedAt = $this->analyzedAt($row);

            // A row with no estimate at all is treated exactly like the never-analyzed sentinel:
            // both mean "no number", and inventing a different path for the second would be a
            // second way for the same absence to reach a report.
            $rowEstimate = $this->number($row, 'row_estimate') ?? -1.0;

            // The sentinel is resolved here and never forwarded. `Estimate` would refuse it anyway;
            // catching it at the reader is what turns "the value type threw" into "this table has
            // no row count, and here is why".
            if ($rowEstimate < 0) {
                $skips[] = CatalogSkip::for(
                    SchemaObjectType::Table,
                    $requested,
                    SkipReason::NotReadable,
                    'the server reports no row estimate for this table — it has never been analyzed',
                );
            }

            $tables[] = new TableStatistics(
                $requested,
                $rowEstimate < 0 ? null : $this->rowCount((int) round($rowEstimate), $analyzedAt),
                $this->bytes($row, 'table_bytes', EstimateSource::TableBytes),
                $this->bytes($row, 'index_bytes', EstimateSource::IndexBytes),
                $this->bytes($row, 'total_bytes', EstimateSource::TotalBytes),
                $this->indexesOf($serverName, $requested, $indexRows),
            );
        }

        return $tables;
    }

    /**
     * The name the CALLER used for a server-side name, or null when it asked about neither.
     *
     * The reverse of {@see self::serverName()}, and it exists so a snapshot answers under the
     * spelling the request used: `forTable()` and `unanswered()` both compare against the request,
     * and a reading that reported `acme_orders` for a request about `orders` would look to both of
     * them like a table nobody asked for beside a table nobody answered.
     *
     * Which requested object this row answers, matched on the SAME two forms the query offered.
     *
     * The query gained a bare arm so that `orders` — what a Laravel migration actually says — finds
     * `public.orders`. Matching the way back on the composed name alone undid exactly that: the row
     * came out of the server and was then dropped here, so the reading looked empty and nothing was
     * ever weighed. The fix is only complete when both directions agree.
     *
     * A requested name CONTAINING a dot is matched composed-only. That is not an oversight: it was
     * spelled qualified, and letting it also match a bare `relname` would make `public.orders` match
     * a table literally named `public.orders` in another schema.
     */
    private function requestedNameFor(StatisticsRequest $request, string $serverName, string $bareName): ?string
    {
        foreach ($request->objects as $object) {
            $asked = $this->serverName($object, $request->tablePrefix);

            if ($asked === $serverName) {
                return $object;
            }

            if (! str_contains($asked, '.') && $asked === $bareName) {
                return $object;
            }
        }

        return null;
    }

    /**
     * The row estimate, always marked as one, carrying whatever freshness the server reported.
     *
     * Three ways out, and they are not interchangeable. A timestamp means the statistics behind this
     * number were refreshed then. No timestamp on a table that HAS a row estimate means the counters
     * were reset or the statistics view is not answering — the age is unknown, which is not the same
     * as never collected, and the difference is whether an ANALYZE would help.
     */
    private function rowCount(int $value, ?DateTimeImmutable $analyzedAt): Estimate
    {
        return $analyzedAt instanceof DateTimeImmutable
            ? Estimate::measured($value, EstimateSource::RowCount, $analyzedAt)
            : Estimate::freshnessUnknown($value, EstimateSource::RowCount);
    }

    /**
     * A byte count, exact at the moment of the read.
     *
     * PostgreSQL's size functions stat the files while answering, so these are measurements rather
     * than remembered numbers — the reason the same quantity is an estimate on another engine, and
     * the reason the precision belongs to the driver rather than to the quantity.
     */
    private function bytes(object $row, string $key, EstimateSource $source): ?Estimate
    {
        $value = $this->number($row, $key);

        return $value === null ? null : Estimate::exact((int) $value, $source);
    }

    /**
     * A column read as text, or the empty string when the server did not answer with a scalar.
     *
     * The same shape the other PostgreSQL readers use: the driver hands back untyped rows, so the
     * narrowing happens once per column rather than being asserted over the whole result.
     */
    private function text(object $row, string $key): string
    {
        $value = $row->{$key} ?? null;

        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * A column read as a number, or null when the server answered with nothing usable.
     *
     * Null rather than zero, everywhere. A size that could not be read is an absence the snapshot
     * explains with a skip; a zero would be a number that reads as "this is tiny", which is the one
     * wrong answer that never looks wrong.
     */
    private function number(object $row, string $key): ?float
    {
        $value = $row->{$key} ?? null;

        return is_numeric($value) ? (float) $value : null;
    }

    /**
     * The later of the two ANALYZE timestamps, or null when neither ran.
     *
     * Both are consulted because either one refreshes the statistics: a table that autovacuum
     * analyzed last night is not stale merely because nobody typed ANALYZE. Reading only the manual
     * one would report most healthy tables as having unknown freshness.
     */
    private function analyzedAt(object $row): ?DateTimeImmutable
    {
        $stamps = array_values(array_filter(
            [$row->last_analyze ?? null, $row->last_autoanalyze ?? null],
            static fn (mixed $stamp): bool => is_string($stamp) && $stamp !== '',
        ));

        if ($stamps === []) {
            return null;
        }

        $parsed = array_values(array_filter(array_map(
            static function (string $stamp): ?DateTimeImmutable {
                try {
                    return new DateTimeImmutable($stamp);
                } catch (Throwable) {
                    // A timestamp this package cannot parse is not a reason to lose the row count
                    // that came with it. The freshness becomes unknown, which is honest.
                    return null;
                }
            },
            $stamps,
        )));

        if ($parsed === []) {
            return null;
        }

        usort($parsed, static fn (DateTimeImmutable $a, DateTimeImmutable $b): int => $b <=> $a);

        return $parsed[0];
    }

    /**
     * @param  list<mixed>  $indexRows
     * @return list<IndexStatistics>
     */
    private function indexesOf(string $serverName, string $requested, array $indexRows): array
    {
        $indexes = [];
        $dot = strrpos($requested, '.');
        $prefix = $dot === false ? '' : substr($requested, 0, $dot + 1);

        foreach ($indexRows as $row) {
            if (! is_object($row)) {
                continue;
            }

            if ($this->text($row, 'schema_name').'.'.$this->text($row, 'table_name') !== $serverName) {
                continue;
            }

            // Named in the requested object's own schema, so an index reads as belonging to the
            // table the caller asked about rather than to a qualified name it never used.
            $indexes[] = new IndexStatistics(
                $prefix.$this->text($row, 'index_name'),
                $this->bytes($row, 'index_bytes', EstimateSource::IndexBytes),
            );
        }

        return $indexes;
    }

    /**
     * The capacity picture: how much the database occupies, and a named absence for what is left.
     *
     * `pg_database_size(current_database())` answers to any role that can connect, so the size half
     * is not the part that degrades. The free half has no SQL at all — which is why it is a skip
     * with a reason rather than a zero, and why the snapshot goes partial when this is all there is.
     *
     * @param  list<CatalogSkip>  $skips
     * @return list<StorageHeadroom>
     */
    #[RawSql(reason: 'reads the sequence ceiling against the column type; the answer lives in the catalog and nowhere a model could reach')]
    private function headroom(ReaderSession $session, array &$skips): array
    {
        try {
            $rows = array_values($session->read(static fn (Connection $db): array => $db->select(
                'select current_database() as name, pg_database_size(current_database()) as used_bytes',
            )));
        } catch (Throwable $error) {
            $skips[] = DatabaseErrorTranslator::skipFor(SchemaObjectType::Database, 'database size', $error);

            return [];
        }

        $row = $rows[0] ?? null;

        if (! is_object($row)) {
            return [];
        }

        $name = $this->text($row, 'name');
        $used = $this->number($row, 'used_bytes');

        if ($name === '' || $used === null) {
            return [];
        }

        return [StorageHeadroom::sizeOnly(
            $name,
            Estimate::exact((int) $used, EstimateSource::StorageUsedBytes),
            CatalogSkip::for(
                SchemaObjectType::Database,
                $name,
                SkipReason::NotReadable,
                'PostgreSQL reports no free space for the volume its data directory sits on — there '
                .'is no SQL for it, and a guessed number would be worse than a named absence',
            ),
        )];
    }
}
