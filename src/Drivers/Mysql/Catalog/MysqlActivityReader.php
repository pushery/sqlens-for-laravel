<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Catalog;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\Activity\ActivityRequest;
use Pushery\SQLens\Catalog\Activity\ActivitySnapshot;
use Pushery\SQLens\Catalog\Activity\LockMode;
use Pushery\SQLens\Catalog\Activity\LockWait;
use Pushery\SQLens\Catalog\Activity\LongRunningSession;
use Pushery\SQLens\Catalog\Activity\ReplicationState;
use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Catalog\Degradation\DatabaseErrorTranslator;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Catalog\SkipReason;
use Pushery\SQLens\Contracts\ActivityReader;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Throwable;

/**
 * What this MySQL server is DOING right now.
 *
 * The sibling of the PostgreSQL activity reader, and — as with the statistics pair — not a
 * translation of it. The two engines withhold state in opposite ways, and a reader that assumed
 * either shape would be blind on the other.
 *
 * ## The silent narrowing here is by ROW, and its detector is a different view
 *
 * Measured on MySQL 8.4.10 with a role holding only `SELECT` on the application schema: every
 * `performance_schema` view and `information_schema.INNODB_TRX` refuse LOUDLY (`42000`, error 1142
 * or 1227), which the error translator already turns into a named skip. Exactly one view does not:
 * `information_schema.PROCESSLIST` answers with the reading's OWN session and nothing else — one
 * row where a privileged role sees the whole server, and no error at all.
 *
 * That narrowing cannot be detected from its own answer: one row is a quiet server and a blind role
 * equally. But `performance_schema.threads` is gated by the SAME `PROCESS` privilege and refuses
 * out loud — so the refusal of one view is the detector for the silence of the other. This reader
 * asks both and uses the first to qualify the second. No `SHOW GRANTS`, no parsing of grant strings:
 * the server says it, you only have to ask the right view.
 *
 * ## Two lock layers, not one
 *
 * `metadata_locks` answers "is DDL blocked", `data_lock_waits` answers "are rows contended". For a
 * deploy the first matters more — InnoDB online DDL needs a brief exclusive metadata lock at each
 * end, and an open transaction on the target table blocks precisely that moment — but both belong in
 * one snapshot, because a migration blocked by either is blocked.
 *
 * `data_lock_waits` carries no relation of its own (thread, transaction and lock IDs only), so it is
 * joined to `data_locks` for the object. A wait chain that could not say WHICH table is queueing is
 * nearly worthless to a preflight.
 */
final readonly class MysqlActivityReader implements ActivityReader
{
    /**
     * MySQL's metadata-lock types, mapped to what they BLOCK.
     *
     * `SHARED_UPGRADABLE` is the entry worth checking twice. Its name reads like "shared but
     * restricted", and a documentation-only mapping lands it on `SharedNoWrite`. It is held during
     * online DDL, allows reads AND writes, and blocks other DDL — which is exactly what
     * `MaintenanceExclusive` means, and the same role PostgreSQL's `ShareUpdateExclusiveLock` plays.
     *
     * `INTENTION_EXCLUSIVE` is the most common type on a live server and the least alarming: a
     * session announcing it may want something stronger later. It blocks a schema change and
     * nothing an application does.
     *
     * A type absent from this map is NOT dropped — see {@see self::metadataWaits()}.
     */
    private const array LOCK_TYPES = [
        'SHARED' => LockMode::Shared,
        'SHARED_HIGH_PRIO' => LockMode::Shared,
        'SHARED_READ' => LockMode::Shared,
        'SHARED_WRITE' => LockMode::SharedWrite,
        'SHARED_WRITE_LOW_PRIO' => LockMode::SharedWrite,
        'INTENTION_EXCLUSIVE' => LockMode::SharedWrite,
        'SHARED_UPGRADABLE' => LockMode::MaintenanceExclusive,
        'SHARED_READ_ONLY' => LockMode::SharedNoWrite,
        'SHARED_NO_WRITE' => LockMode::SharedNoWrite,
        'SHARED_NO_READ_WRITE' => LockMode::Exclusive,
        'EXCLUSIVE' => LockMode::Exclusive,
    ];

    public function __construct(private ReaderSession $session) {}

    #[RawSql(reason: 'performance_schema and information_schema queries; those tables are not models, and the joins an activity picture needs have no builder form')]
    public function read(ActivityRequest $request): ActivitySnapshot
    {
        /** @var list<CatalogSkip> $skips */
        $skips = [];

        $session = $this->session->withBudget($this->session->budget()->narrowedTo($request->budgetMilliseconds));

        // FIRST, because its refusal is what qualifies everything the process list says. Asked after
        // the fact it would still work; asked first it makes the ordering of this method say why it
        // is here.
        $hasProcessPrivilege = $this->hasProcessPrivilege($session, $skips);

        // SECOND, and for the same reason: it qualifies every lock reading below. With
        // `performance_schema` off those views still exist, still answer, and return NO ROWS —
        // which is exactly what an idle server returns. Nothing downstream could tell the two
        // apart, so the question is asked here rather than inferred there.
        $this->requireInstrumentation($session, $skips);

        $transactions = DatabaseErrorTranslator::attemptBounded(
            fn (): array => array_values($session->read(
                fn (Connection $db): array => $db->select($this->transactionQuery(), [$request->longRunningThresholdMs]),
            )),
            SchemaObjectType::Setting,
            'information_schema.INNODB_TRX',
            $session,
            $skips,
        );

        $metadataRows = DatabaseErrorTranslator::attemptBounded(
            fn (): array => array_values($session->read(
                fn (Connection $db): array => $db->select($this->metadataLockQuery()),
            )),
            SchemaObjectType::Table,
            'performance_schema.metadata_locks',
            $session,
            $skips,
        );

        $dataRows = DatabaseErrorTranslator::attemptBounded(
            fn (): array => array_values($session->read(
                fn (Connection $db): array => $db->select($this->dataLockQuery()),
            )),
            SchemaObjectType::Table,
            'performance_schema.data_lock_waits',
            $session,
            $skips,
        );

        // Which of the deploy's own tables each session is HOLDING a metadata lock on, asked only
        // when the caller named some. Without it `relation` on every long runner stays null, and a
        // check matching sessions against its target tables can never match one — the branch reads
        // as "nothing is blocking" on a server where something is.
        $heldRows = $request->objects === []
            ? []
            : DatabaseErrorTranslator::attemptBounded(
                fn (): array => array_values($session->read(
                    // Bound TWICE — once per comparison in the query above.
                    fn (Connection $db): array => $db->select(
                        $this->heldRelationQuery(count($request->objects)),
                        [...$request->objects, ...$request->objects],
                    ),
                )),
                SchemaObjectType::Table,
                'performance_schema.metadata_locks',
                $session,
                $skips,
            );

        if (! $hasProcessPrivilege) {
            $skips[] = CatalogSkip::for(
                SchemaObjectType::Setting,
                'information_schema.PROCESSLIST',
                SkipReason::InsufficientPrivilege,
                'this role holds no PROCESS privilege, so the server\'s state views answer about this '
                .'session alone. The process list does NOT say so — it returns one row and no error, '
                .'which is indistinguishable from a quiet server. performance_schema.threads is gated '
                .'by the same privilege and refuses out loud, which is how the silence was detected.',
            );
        }

        return new ActivitySnapshot(
            $request,
            [...$this->metadataWaits($metadataRows), ...$this->dataWaits($dataRows)],
            $this->longRunners($transactions, $this->heldRelations($heldRows, $request->objects)),
            $request->includeReplication ? $this->replication($session, $skips) : [],
            $skips,
        );
    }

    /**
     * Record it when the server's instrumentation is off, because then silence proves nothing.
     *
     * This is the sharpest silent-green risk on this engine, and it is invisible from the readings
     * themselves: `performance_schema.metadata_locks` and `data_lock_waits` are present and
     * queryable with the instrumentation disabled, and they answer with an empty set. A quiet
     * server and a blind one are byte-for-byte identical downstream.
     *
     * One variable tells them apart, so it is asked rather than guessed. A server that will not
     * answer even that gets no verdict either — an unreadable switch is not an off switch, and
     * claiming it was off would be the same invention in the other direction.
     *
     * @param  list<CatalogSkip>  $skips
     */
    #[RawSql(reason: 'asks @@performance_schema whether the instrumentation exists at all -- the question that has to be answered before any of the rest means anything')]
    private function requireInstrumentation(ReaderSession $session, array &$skips): void
    {
        $enabled = DatabaseErrorTranslator::attemptBounded(
            fn (): array => array_values($session->read(
                fn (Connection $db): array => $db->select('select @@performance_schema as enabled'),
            )),
            SchemaObjectType::Setting,
            'performance_schema',
            $session,
            $skips,
        );

        $row = $enabled[0] ?? null;

        if (! is_object($row)) {
            return;
        }

        $enabledFlag = $this->number($row, 'enabled');

        // A switch this reader could not read is NOT an off switch. Returning here rather than
        // reporting one keeps the invention out in both directions.
        if ($enabledFlag === null || (int) $enabledFlag !== 0) {
            return;
        }

        $skips[] = CatalogSkip::for(
            SchemaObjectType::Setting,
            'performance_schema',
            SkipReason::InstrumentationDisabled,
            'this server runs with performance_schema off, so its lock views answer with an empty '
            .'set rather than an error. That is the same answer a quiet server gives, which is why '
            .'no calm was concluded from it. Enabling it needs a server restart, not a grant.',
        );
    }

    /**
     * Whether this role can see the whole server, established by ASKING for the privilege.
     *
     * The first version inferred it from a sibling view's refusal — `performance_schema.threads`
     * refuses out loud where `information_schema.PROCESSLIST` narrows in silence — and the premise
     * was wrong in a way that produced a silent green. Measured on 8.4.10, four grant combinations:
     *
     * | grants                        | threads  | PROCESSLIST      |
     * |-------------------------------|----------|------------------|
     * | none                          | refused  | 1 row (narrowed) |
     * | PROCESS only                  | REFUSED  | 3 rows (whole)   |
     * | SELECT on performance_schema  | 40 rows  | 1 row (NARROWED) |
     * | both                          | 40 rows  | 3 rows           |
     *
     * `threads` is gated by SELECT on `performance_schema`, not by PROCESS. So the old rule was
     * wrong in both directions, and the third row is the one that mattered: the view answered, the
     * detector reported no problem, and the process list was narrowed anyway. That combination is
     * not exotic — it is what a carefully set-up monitoring account gets.
     *
     * `information_schema.USER_PRIVILEGES` answers the question itself, and every account may read
     * its own row.
     *
     * One honest remainder: PROCESS held through an ACTIVATED ROLE does not appear there. So a
     * negative answer is reported as "no PROCESS privilege is recorded", never as "the list is
     * narrowed" — the error stays on the over-cautious side, which is the only side this package
     * may err on.
     *
     * @param  list<CatalogSkip>  $skips
     */
    #[RawSql(reason: 'asks what the connecting account is granted; a privilege question has no builder form, and getting it wrong would make the reader report absence as cleanliness')]
    private function hasProcessPrivilege(ReaderSession $session, array &$skips): bool
    {
        try {
            $rows = array_values($session->read(static fn (Connection $db): array => $db->select(
                <<<'SQL'
                    select count(*) as granted
                      from information_schema.USER_PRIVILEGES
                     where GRANTEE = concat('\'', substring_index(current_user(), '@', 1), '\'@\'', substring_index(current_user(), '@', -1), '\'')
                       and PRIVILEGE_TYPE = 'PROCESS'
                    SQL,
            )));
        } catch (Throwable $error) {
            // A timeout is not a privilege answer — it says nothing either way, and reporting it as
            // "no PROCESS" would blame a permission for a bound this package set on itself. Any
            // other refusal is recorded too: an unread privilege table leaves the question open,
            // and an open question is not a yes.
            $skips[] = DatabaseErrorTranslator::skipFor(
                SchemaObjectType::Setting,
                'information_schema.USER_PRIVILEGES',
                $error,
            );

            return $session->isOwnTimeout($error);
        }

        $row = $rows[0] ?? null;

        if (! is_object($row)) {
            return false;
        }

        $granted = $this->number($row, 'granted');

        return $granted !== null && (int) $granted > 0;
    }

    /**
     * Long-running transactions, which on this engine is where a blocking session shows up.
     *
     * This view is NOT live. InnoDB serves it from a cache it refuses to refresh more than once per
     * 100 ms, and that cache is global — so an answer here can be up to a tenth of a second old
     * because somebody else read the view, and reading it costs everyone else the same window.
     *
     * That is worth knowing and not worth compensating for. The cache holds a snapshot rather than
     * an empty set, so a transaction old enough to be asked about here was already in it; only a
     * transaction younger than the window can be missing, and one that young is never the answer to
     * "has something been running too long". Sleeping off the window would make every preflight
     * slower to avoid a staleness that cannot reach the verdict. Measured in
     * `tests/MySql/InnodbTrxCacheWindowTest.php`.
     */
    private function transactionQuery(): string
    {
        return <<<'SQL'
            select trx_mysql_thread_id as session_id,
                   trx_state as state,
                   round(timestampdiff(microsecond, trx_started, now(6)) / 1000) as running_for_ms
              from information_schema.INNODB_TRX
             where timestampdiff(microsecond, trx_started, now(6)) / 1000 >= ?
            SQL;
    }

    /**
     * Metadata locks that are WAITING, and who holds the object they wait for.
     *
     * `LOCK_STATUS = 'PENDING'` is the wait; the holder is a granted lock on the same object. The
     * join is on the object rather than on a blocker id because MySQL names no blocker — unlike
     * PostgreSQL's `pg_blocking_pids()`, there is no function that resolves the conflict graph, so
     * the honest answer is "one of these holds it" and the first is reported.
     */
    private function metadataLockQuery(): string
    {
        return <<<'SQL'
            select w.OWNER_THREAD_ID as waiter_thread,
                   wt.PROCESSLIST_ID as waiter_connection,
                   h.OWNER_THREAD_ID as holder_thread,
                   ht.PROCESSLIST_ID as holder_connection,
                   w.LOCK_TYPE as raw_mode,
                   concat(coalesce(w.OBJECT_SCHEMA, ''), '.', coalesce(w.OBJECT_NAME, '')) as relation
              from performance_schema.metadata_locks w
              left join performance_schema.threads wt on wt.THREAD_ID = w.OWNER_THREAD_ID
              left join performance_schema.metadata_locks h
                     on h.OBJECT_SCHEMA <=> w.OBJECT_SCHEMA
                    and h.OBJECT_NAME <=> w.OBJECT_NAME
                    and h.LOCK_STATUS = 'GRANTED'
                    and h.OWNER_THREAD_ID <> w.OWNER_THREAD_ID
              left join performance_schema.threads ht on ht.THREAD_ID = h.OWNER_THREAD_ID
             where w.LOCK_STATUS = 'PENDING'
            SQL;
    }

    /**
     * Row-lock wait chains, joined for the object they are about.
     *
     * `data_lock_waits` carries thread, transaction and lock IDs and nothing else — measured. A wait
     * chain that could not name the table is nearly worthless to a preflight, so the object comes
     * from `data_locks`.
     */
    private function dataLockQuery(): string
    {
        return <<<'SQL'
            select w.REQUESTING_THREAD_ID as waiter_thread,
                   wt.PROCESSLIST_ID as waiter_connection,
                   w.BLOCKING_THREAD_ID as holder_thread,
                   ht.PROCESSLIST_ID as holder_connection,
                   coalesce(l.LOCK_MODE, '') as raw_mode,
                   concat(coalesce(l.OBJECT_SCHEMA, ''), '.', coalesce(l.OBJECT_NAME, '')) as relation
              from performance_schema.data_lock_waits w
              left join performance_schema.data_locks l on l.ENGINE_LOCK_ID = w.REQUESTING_ENGINE_LOCK_ID
              left join performance_schema.threads wt on wt.THREAD_ID = w.REQUESTING_THREAD_ID
              left join performance_schema.threads ht on ht.THREAD_ID = w.BLOCKING_THREAD_ID
            SQL;
    }

    /**
     * Which of the focus tables each session currently HOLDS a metadata lock on.
     *
     * The opposite filter from {@see self::metadataLockQuery()}, which reports `PENDING` rows — the
     * waiters. A transaction sitting on the deploy's target table is not waiting for anything, so it
     * appears in no pending row, and it is exactly the thing that turns InnoDB's online DDL into an
     * outage: the algorithm is online in the MIDDLE and needs a brief exclusive metadata lock at both
     * ends, which an open transaction on the table denies it.
     *
     * Bound to the focus set rather than to the whole server: `metadata_locks` carries a row per held
     * lock, and a busy instance has thousands.
     *
     * The join to `threads` is what makes the key line up. Long runners come from
     * `INNODB_TRX.trx_mysql_thread_id`, which is a CONNECTION id; `metadata_locks` records an
     * `OWNER_THREAD_ID`, which is not the same number. Keying on the raw thread id would produce a
     * map that never matches and would look exactly like a quiet server.
     *
     * @param  list<mixed>  $rows
     * @param  list<string>  $objects  the focus set, so the answer speaks the caller's vocabulary
     * @return array<string, string> connection id => the first focus table it holds, in a stable order
     */
    private function heldRelations(array $rows, array $objects = []): array
    {
        $held = [];

        foreach ($rows as $row) {
            if (! is_object($row)) {
                continue;
            }

            $connection = $this->text($row, 'session_id');
            // In the CALLER'S vocabulary — see the PostgreSQL sibling. Handing back `db.orders` for a
            // focus set holding the bare `orders` would find the lock and then fail to match it.
            $qualified = $this->text($row, 'relation');
            $bare = $this->text($row, 'bare_relation');

            $relation = in_array($qualified, $objects, true)
                ? $qualified
                : (in_array($bare, $objects, true) ? $bare : $qualified);

            // First wins, and the query orders by relation so "first" is stable across runs. A
            // session holding two of the deploy's tables produces one finding naming one of them —
            // the deploy is blocked either way.
            if ($connection !== '' && $relation !== '' && ! isset($held[$connection])) {
                $held[$connection] = $relation;
            }
        }

        return $held;
    }

    /**
     * Granted metadata locks on named tables only — the focus set is bound, never interpolated.
     *
     * Matched TWO ways, for the reason the PostgreSQL sibling documents at length: a canonical target
     * keeps the qualification the source wrote, and a Laravel migration writes none, so comparing a
     * bare `orders` against the composed `db.orders` matched nothing and the branch went quiet on a
     * server that really was holding a metadata lock.
     *
     * `l.OBJECT_SCHEMA = database()` is this engine's answer to "would an unqualified reference find
     * this table" — MySQL resolves an unqualified name against the connected database, and asking the
     * server beats assuming a name.
     */
    private function heldRelationQuery(int $objectCount): string
    {
        $placeholders = implode(', ', array_fill(0, $objectCount, '?'));

        return <<<SQL
            select t.PROCESSLIST_ID as session_id,
                   concat(coalesce(l.OBJECT_SCHEMA, ''), '.', coalesce(l.OBJECT_NAME, '')) as relation,
                   coalesce(l.OBJECT_NAME, '') as bare_relation
              from performance_schema.metadata_locks l
              join performance_schema.threads t on t.THREAD_ID = l.OWNER_THREAD_ID
             where l.LOCK_STATUS = 'GRANTED'
               and t.PROCESSLIST_ID is not null
               and t.PROCESSLIST_ID <> connection_id()
               and (
                     concat(coalesce(l.OBJECT_SCHEMA, ''), '.', coalesce(l.OBJECT_NAME, '')) in ({$placeholders})
                  or (l.OBJECT_NAME in ({$placeholders}) and l.OBJECT_SCHEMA = database())
                   )
             order by t.PROCESSLIST_ID, relation
            SQL;
    }

    /**
     * @param  list<mixed>  $rows
     * @param  array<string, string>  $held  connection id => the focus table it is sitting on
     * @return list<LongRunningSession>
     */
    private function longRunners(array $rows, array $held = []): array
    {
        $sessions = [];

        foreach ($rows as $row) {
            if (! is_object($row)) {
                continue;
            }

            $duration = $this->number($row, 'running_for_ms');
            $state = $this->text($row, 'state');
            if ($duration === null) {
                continue;
            }
            if ($state === '') {
                continue;
            }

            $connection = $this->text($row, 'session_id');

            $sessions[] = new LongRunningSession(
                $this->sessionLabel($connection, ''),
                (int) $duration,
                $state,
                $held[$connection] ?? null,
            );
        }

        return $sessions;
    }

    /**
     * @param  list<mixed>  $rows
     * @return list<LockWait>
     */
    private function metadataWaits(array $rows): array
    {
        return $this->waitsFrom($rows, static fn (string $raw): ?LockMode => self::LOCK_TYPES[$raw] ?? null);
    }

    /**
     * Row-lock waits, whose mode vocabulary is InnoDB's rather than the metadata layer's.
     *
     * `X` and `S` with optional modifiers, not the `SHARED_*` names — so they go through their own
     * mapping. Anything else keeps its raw spelling and the snapshot marks the reading partial,
     * which is the same refusal to drop a row that the metadata layer gets.
     *
     * @param  list<mixed>  $rows
     * @return list<LockWait>
     */
    private function dataWaits(array $rows): array
    {
        return $this->waitsFrom($rows, static fn (string $raw): ?LockMode => match (true) {
            str_starts_with($raw, 'X') => LockMode::Exclusive,
            str_starts_with($raw, 'S') => LockMode::SharedNoWrite,
            default => null,
        });
    }

    /**
     * How a session is named, and why the two spellings are not interchangeable.
     *
     * `performance_schema` identifies a session by `THREAD_ID`; everything a person can act with —
     * `SHOW PROCESSLIST`, `KILL`, `INNODB_TRX` — identifies it by the connection id. They are
     * different numbering spaces for the same session. Reporting the first would hand out a number
     * that correlates with nothing else in the same snapshot and that `KILL` does not accept, which
     * is what a live wait caught this reader doing: the lock layers spoke thread ids while the
     * transaction layer spoke connection ids, so a blocker and a long-runner could never be
     * recognized as one session.
     *
     * A background thread genuinely has no connection id, and that case keeps the thread spelling
     * rather than inventing one — "held by something you cannot KILL" is the honest answer, and a
     * fabricated id would be worse than an unfamiliar one.
     */
    private function sessionLabel(string $connectionId, string $threadId): string
    {
        return $connectionId !== ''
            ? 'connection='.$connectionId
            : 'thread='.$threadId;
    }

    /**
     * @param  list<mixed>  $rows
     * @param  callable(string): ?LockMode  $map
     * @return list<LockWait>
     */
    private function waitsFrom(array $rows, callable $map): array
    {
        $waits = [];

        foreach ($rows as $row) {
            if (! is_object($row)) {
                continue;
            }

            $raw = $this->text($row, 'raw_mode');
            $holderThread = $this->text($row, 'holder_thread');

            if ($raw === '') {
                continue;
            }

            $waits[] = new LockWait(
                $this->sessionLabel($this->text($row, 'waiter_connection'), $this->text($row, 'waiter_thread')),
                $holderThread === ''
                    ? null
                    : $this->sessionLabel($this->text($row, 'holder_connection'), $holderThread),
                $this->text($row, 'relation'),
                $map($raw),
                $raw,
            );
        }

        return $waits;
    }

    /**
     * How far this instance is behind the source it replicates from.
     *
     * The mirror image of the PostgreSQL reader's question, and deliberately so: PostgreSQL reports
     * replication from the PRIMARY's view of its replicas, MySQL from the REPLICA's view of its
     * source. So an empty answer here means "this is not a replica" rather than "the replicas are
     * caught up" — and it is reported as such, because the two would otherwise read alike.
     *
     * @param  list<CatalogSkip>  $skips
     * @return list<ReplicationState>
     */
    #[RawSql(reason: 'reads replication status, which MySQL exposes only through SHOW and performance_schema -- neither has a builder equivalent')]
    private function replication(ReaderSession $session, array &$skips): array
    {
        $before = count($skips);

        $rows = DatabaseErrorTranslator::attemptBounded(
            fn (): array => array_values($session->read(
                fn (Connection $db): array => $db->select(
                    'select CHANNEL_NAME as channel, SERVICE_STATE as state'
                    .' from performance_schema.replication_connection_status',
                ),
            )),
            SchemaObjectType::Setting,
            'performance_schema.replication_connection_status',
            $session,
            $skips,
        );

        // Whether the READ itself failed. It decides whether the emptiness below may be read as an
        // answer at all — see the conclusion further down, which must not be drawn from a view that
        // refused.
        $refused = count($skips) > $before;

        $states = [];

        foreach ($rows as $row) {
            if (! is_object($row)) {
                continue;
            }

            $channel = $this->text($row, 'channel');

            $states[] = new ReplicationState($channel === '' ? 'default' : $channel, $this->text($row, 'state'));
        }

        // "Not a replica" is a claim about the SERVER, and it may only be made from a reading that
        // happened. A refused view is empty for a reason that has nothing to do with replication,
        // and concluding from it would be the exact inference this package forbids everywhere else:
        // reading blindness as an answer. Measured on a role without SELECT on performance_schema,
        // the reading previously reported BOTH "you may not read this" AND "this instance
        // replicates from nothing" — the second of which it could not know.
        if ($states === [] && ! $refused) {
            $skips[] = CatalogSkip::for(
                SchemaObjectType::Setting,
                'performance_schema.replication_connection_status',
                SkipReason::NotReadable,
                'this instance replicates from nothing, so it has no lag of its own to report. MySQL '
                .'answers replication from the REPLICA\'s side, so an empty result here means "not a '
                .'replica" rather than "caught up" — and the two would otherwise read alike.',
            );
        }

        return $states;
    }

    private function text(object $row, string $key): string
    {
        $value = $row->{$key} ?? null;

        return is_scalar($value) ? (string) $value : '';
    }

    private function number(object $row, string $key): ?float
    {
        $value = $row->{$key} ?? null;

        return is_numeric($value) ? (float) $value : null;
    }
}
