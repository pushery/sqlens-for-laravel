<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Statistics;

use Pushery\SQLens\Catalog\CatalogCompleteness;
use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Catalog\CatalogSnapshot;
use Pushery\SQLens\Catalog\SkipReason;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * One reading of the server's statistics: how big the objects in scope are, how much room their
 * storage has, what could NOT be read, and whether that is the whole picture.
 *
 * The sibling of {@see CatalogSnapshot}, built the same way for the same
 * reasons. The parts are inseparable: numbers alone cannot be judged (about which objects? asked
 * for under which scope?), cannot be compared between runs, and — worst — cannot be told apart from
 * a reading that got half of what it asked for, because a half-read set of statistics looks exactly
 * like a complete one to everything downstream. The consumer here is a severity escalation, so the
 * failure has a shape: a migration weighted as safe because the reading that would have shown the
 * table is enormous quietly returned nothing.
 *
 * ## This is CONTEXT, not a subject
 *
 * The snapshot deliberately implements no `Subject` interface, and an architecture test holds the
 * subject set closed at three. A rule receiving statistics through the ordinary dispatch would be
 * reading an ANALYZE-dependent number as an input to a verdict, which is the master plan's ninth
 * pitfall: the same schema would pass and fail depending on when statistics were last refreshed.
 * Statistics attach to a FINDING, marked for what they are.
 *
 * ## Determinism is a property of the type, not of the reader
 *
 * Tables, their indexes and the skips are sorted HERE, on construction, rather than left to
 * whichever order the query returned. Two readings of an unchanged database must serialize
 * byte-identically, or a comparison reports the ordering of a query plan as a change. Sorting in
 * one place means no reader can forget and no reader can sort differently.
 *
 * ## Completeness is derived, never asserted
 *
 * A reader does not get to say its reading was complete; it is computed from the skips. An
 * optimistic reader could otherwise report `complete` while its own skip list contradicted it, and
 * the field would be worth less than nothing. The headroom readings' skips are folded in for the
 * same reason: a free-space number nobody could read makes the reading partial whether or not the
 * reader thought to say so.
 */
final readonly class StatisticsSnapshot
{
    /** @var list<TableStatistics> */
    public array $tables;

    /** @var list<StorageHeadroom> */
    public array $headroom;

    /** @var list<CatalogSkip> */
    public array $skips;

    public CatalogCompleteness $completeness;

    /**
     * @param  list<TableStatistics>  $tables
     * @param  list<StorageHeadroom>  $headroom
     * @param  list<CatalogSkip>  $skips  what the reader could not deliver; the headroom readings'
     *                                    own skips are added here automatically, so a caller never
     *                                    has to remember to copy them across
     */
    public function __construct(
        public StatisticsRequest $request,
        array $tables = [],
        array $headroom = [],
        array $skips = [],
    ) {
        usort($tables, static fn (TableStatistics $a, TableStatistics $b): int => $a->qualifiedName <=> $b->qualifiedName);
        usort($headroom, static fn (StorageHeadroom $a, StorageHeadroom $b): int => $a->reference <=> $b->reference);

        foreach ($headroom as $reading) {
            foreach ($reading->skips as $skip) {
                $skips[] = $skip;
            }
        }

        // An object somebody asked about that came back with nothing gets a NAMED skip, derived
        // here rather than left to each driver to remember.
        //
        // The list alone was not enough, and the case that showed it is MySQL's: `information_schema`
        // narrows PER OBJECT, so a role holding SELECT on one table and not its neighbor sees
        // exactly one of them — no error, no empty result, nothing to be suspicious of. Measured.
        // A consumer looking at `gaps()` to answer "why is this partial?" would have been told
        // nothing about the table that vanished.
        //
        // `not_readable` rather than `insufficient_privilege`, and the imprecision is the honest
        // part: a catalog that returns no row cannot say WHICH of the two happened, and that reason
        // is the one whose definition already covers both — "it does not exist on this server, or
        // the connection lost access to it". Claiming a privilege problem would be inventing a
        // diagnosis; claiming a dropped table would be worse.
        $alreadyNamed = array_map(static fn (CatalogSkip $skip): string => $skip->reference, $skips);

        foreach ($this->objectsWithoutRows($request, $tables) as $object) {
            // An object the reader ALREADY said something about keeps that answer. Deriving a
            // second skip here would not merely duplicate: for an object excluded by configuration
            // it would turn a DECISION into a gap, so every deliberate exclusion would read as a
            // failure and `gaps()` would stop meaning what it says.
            if (in_array($object, $alreadyNamed, true)) {
                continue;
            }

            $skips[] = CatalogSkip::for(
                SchemaObjectType::Table,
                $object,
                SkipReason::NotReadable,
                'the catalog returned no row for this object. On MySQL that is what a dropped table '
                .'AND a table the connecting account holds no privilege on both look like, so no '
                .'diagnosis is offered here — but the object was asked about and is missing from '
                .'the reading, which is what a size-weighted verdict must not overlook.',
            );
        }

        usort($skips, static fn (CatalogSkip $a, CatalogSkip $b): int => $a->sortKey() <=> $b->sortKey());

        $this->tables = $tables;
        $this->headroom = $headroom;
        $this->skips = $skips;
        $this->completeness = $this->completenessOf($this->skips);
    }

    /** Whether anything in scope went unread — the question a consumer must ask before trusting silence. */
    public function isPartial(): bool
    {
        return $this->completeness === CatalogCompleteness::Partial;
    }

    /**
     * The skips where something in scope went UNREAD, as opposed to being deliberately excluded.
     *
     * The same split the catalog snapshot makes, and for the same reason: a caller answering "why
     * is this partial?" wants the gaps, not the decisions, which would bury the real answer under
     * expected noise. Nothing disappears — both remain in `$skips`.
     *
     * @return list<CatalogSkip>
     */
    public function gaps(): array
    {
        return array_values(array_filter(
            $this->skips,
            static fn (CatalogSkip $skip): bool => $skip->reason->leavesTheReadingIncomplete(),
        ));
    }

    /**
     * What the reading established about one table, or null when it established nothing.
     *
     * Null rather than an empty {@see TableStatistics}, deliberately. An empty one would answer
     * every question with "no number", which reads as a table that was measured and found to have
     * none — and a consumer would have no way to tell it from a table the reading never reached.
     */
    public function forTable(string $qualifiedName): ?TableStatistics
    {
        foreach ($this->tables as $table) {
            if ($table->qualifiedName === $qualifiedName) {
                return $table;
            }
        }

        return null;
    }

    /**
     * The requested objects no row arrived for — the same question `unanswered()` answers, asked
     * before `$this->tables` is assigned so the constructor can name them.
     *
     * @param  list<TableStatistics>  $tables
     * @return list<string>
     */
    private function objectsWithoutRows(StatisticsRequest $request, array $tables): array
    {
        $answered = array_map(static fn (TableStatistics $table): string => $table->qualifiedName, $tables);

        return array_values(array_filter(
            $request->objects,
            static fn (string $object): bool => ! in_array($object, $answered, true),
        ));
    }

    /**
     * The objects the request asked about that the reading came back with nothing for.
     *
     * The accessor a consumer needs before weighting anything, and the one a snapshot without it
     * would make easy to forget: a table missing from `$tables` is invisible to every loop over
     * them. This turns that absence into a list somebody can look at.
     *
     * @return list<string>
     */
    public function unanswered(): array
    {
        $answered = array_map(static fn (TableStatistics $table): string => $table->qualifiedName, $this->tables);

        return array_values(array_filter(
            $this->request->objects,
            static fn (string $object): bool => ! in_array($object, $answered, true),
        ));
    }

    /**
     * A stable digest of this reading.
     *
     * The request is part of it: two readings that differ only in the objects they asked about are
     * different readings, and a hash that ignored that would let a comparator treat them as the same
     * picture of the same database.
     */
    public function hash(): string
    {
        return hash('sha256', $this->serialize());
    }

    /**
     * The canonical serialization — the one a hash is taken over and a golden file holds.
     *
     * `JSON_THROW_ON_ERROR` rather than a silent `false`: a snapshot that could not be serialized
     * must not become an empty digest that two different databases would share.
     */
    public function serialize(): string
    {
        return json_encode($this->fingerprint(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * The stable half of this snapshot — its IDENTITY rather than its full report.
     *
     * A fingerprint answers "has this changed since last time". Two values in `toArray()` move
     * without anything about the schema changing, and including them makes the digest report a
     * difference on every reading while saying nothing about what it describes:
     *
     * - **`headroom`** is `pg_database_size` and free space. It moves whenever ANYTHING writes to
     *   the instance — another connection, autovacuum, a temporary table in a neighboring test.
     * - **`measured_at`** is when the server last ran ANALYZE. It moves when autoanalyze does.
     *
     * Measured, and it is why this method exists: the deploy determinism arm passed in isolation
     * and failed inside a full suite run, because the full run writes. The digest was reporting the
     * clock.
     *
     * Both stay in `toArray()`. The REPORT should carry the number and the freshness — a reader
     * weighing an escalation needs to know the row estimate is three weeks old. The IDENTITY should
     * not, because "the numbers are the same" and "they were taken at the same instant" are
     * different claims, and only the first is what a digest is asked for.
     *
     * @return array<string, mixed>
     */
    public function fingerprint(): array
    {
        $projection = $this->toArray();

        unset($projection['headroom']);

        $projection['tables'] = array_map(
            static function (array $table): array {
                foreach (['rows', 'table_bytes', 'index_bytes', 'total_bytes'] as $key) {
                    if (is_array($table[$key] ?? null)) {
                        unset($table[$key]['measured_at']);
                    }
                }

                return $table;
            },
            $projection['tables'],
        );

        return $projection;
    }

    /**
     * @return array{request: array<string, mixed>, completeness: string, tables: list<array<string, mixed>>, headroom: list<array<string, mixed>>, skips: list<array<string, mixed>>}
     */
    public function toArray(): array
    {
        return [
            'request' => $this->request->toArray(),
            'completeness' => $this->completeness->value,
            'tables' => array_map(static fn (TableStatistics $table): array => $table->toArray(), $this->tables),
            'headroom' => array_map(static fn (StorageHeadroom $reading): array => $reading->toArray(), $this->headroom),
            'skips' => array_map(static fn (CatalogSkip $skip): array => $skip->toArray(), $this->skips),
        ];
    }

    /** @param  list<CatalogSkip>  $skips */
    private function completenessOf(array $skips): CatalogCompleteness
    {
        $unread = array_any($skips, static fn (CatalogSkip $skip): bool => $skip->reason->leavesTheReadingIncomplete());

        return $unread ? CatalogCompleteness::Partial : CatalogCompleteness::Complete;
    }
}
