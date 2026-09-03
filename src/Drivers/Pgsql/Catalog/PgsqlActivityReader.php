<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Catalog;

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

/**
 * What this PostgreSQL server is DOING right now — observation, never participation.
 *
 * ## The masked view is the reason this class is careful rather than short
 *
 * Measured on PostgreSQL 18 with an ordinary role holding nothing but `CONNECT`, against nineteen
 * foreign sessions:
 *
 * | column | unprivileged | superuser |
 * |---|---|---|
 * | `pid` | 19 non-null | — |
 * | `state` | **0** | 11 |
 * | `xact_start` | **0** | 2 |
 * | `query_start` | **0** | — |
 * | `wait_event_type` | **0** | 18 |
 *
 * `pg_stat_activity` **does not refuse**. It answers with every row present and every useful column
 * empty. So the obvious implementation — `where xact_start < now() - interval` — returns nothing on
 * a server with hours-old transactions and reports that nobody is running long. That is the silent
 * green this whole package is built against, and it arrives without a single error.
 *
 * The detection is inside the answer: rows exist whose `state` is null, so `count(*)` exceeding
 * `count(state)` means the view is masked. This reader counts both in the same statement and turns
 * the difference into a named skip. It never filters and returns empty.
 *
 * `pg_locks` measured the opposite way: fully readable to the same unprivileged role, 3832 rows.
 * The lock GRAPH survives where the session ATTRIBUTES do not, which is what makes an honest
 * reading possible at all.
 *
 * ## The instance's role is reported, never assumed
 *
 * Replication is read from the primary's view of its replicas, and a standby has no such view —
 * asking there is not an error, it is a question with no subject. `pg_is_in_recovery()` answers
 * which one this connection reached, and the answer travels as a skip rather than as an empty list.
 */
final readonly class PgsqlActivityReader implements ActivityReader
{
    /**
     * PostgreSQL's eight lock modes, mapped to what they BLOCK.
     *
     * Two entries repay reading. `ExclusiveLock` is not this package's `Exclusive`: it conflicts
     * with everything except `AccessShareLock`, so the application keeps READING and fails on
     * writes — which is `SharedNoWrite`. Only `AccessExclusiveLock` stops reads, and mapping the two
     * together would have reported an outage where there was a write freeze.
     *
     * `ShareUpdateExclusiveLock` is the one most easily mistaken for harmless: it blocks nothing an
     * application does, and it blocks `VACUUM`, `ANALYZE` and another `CREATE INDEX CONCURRENTLY` —
     * so a migration built to be online queues behind it indefinitely while every dashboard is green.
     *
     * A mode absent from this map is NOT dropped. See {@see self::lockWaits()}.
     */
    private const array LOCK_MODES = [
        'AccessShareLock' => LockMode::Shared,
        'RowShareLock' => LockMode::Shared,
        'RowExclusiveLock' => LockMode::SharedWrite,
        'ShareUpdateExclusiveLock' => LockMode::MaintenanceExclusive,
        'ShareLock' => LockMode::SharedNoWrite,
        'ShareRowExclusiveLock' => LockMode::SharedNoWrite,
        'ExclusiveLock' => LockMode::SharedNoWrite,
        'AccessExclusiveLock' => LockMode::Exclusive,
    ];

    public function __construct(private ReaderSession $session) {}

    #[RawSql(reason: 'reads pg_stat_activity and pg_locks; the statistics views are not models and the joins an activity picture needs have no builder form')]
    public function read(ActivityRequest $request): ActivitySnapshot
    {
        /** @var list<CatalogSkip> $skips */
        $skips = [];

        $session = $this->session->withBudget($this->session->budget()->narrowedTo($request->budgetMilliseconds));

        $activity = DatabaseErrorTranslator::attemptBounded(
            fn (): array => array_values($session->read(
                fn (Connection $db): array => $db->select($this->activityQuery(), [$request->longRunningThresholdMs]),
            )),
            SchemaObjectType::Setting,
            'pg_stat_activity',
            $session,
            $skips,
        );

        $lockRows = DatabaseErrorTranslator::attemptBounded(
            fn (): array => array_values($session->read(
                fn (Connection $db): array => $db->select($this->lockQuery()),
            )),
            SchemaObjectType::Table,
            'pg_locks',
            $session,
            $skips,
        );

        $this->recordMasking($activity, $skips);

        // Which of the deploy's own relations each session is HOLDING, asked only when the caller
        // named some. Without this the relation on every long runner stays null, and a check that
        // matches sessions against its target tables can never match one — the branch reads as
        // "nothing is blocking" on a server where something is.
        $heldRows = $request->objects === []
            ? []
            : DatabaseErrorTranslator::attemptBounded(
                fn (): array => array_values($session->read(
                    // Bound TWICE — once per comparison in the query above. The two IN lists carry
                    // the same values on purpose; see `heldRelationQuery()` for why offering every
                    // object to both is safer than deciding which form it is.
                    fn (Connection $db): array => $db->select(
                        $this->heldRelationQuery(count($request->objects)),
                        [...$request->objects, ...$request->objects],
                    ),
                )),
                SchemaObjectType::Table,
                'pg_locks',
                $session,
                $skips,
            );

        return new ActivitySnapshot(
            $request,
            $this->lockWaits($lockRows),
            $this->longRunners($activity, $this->heldRelations($heldRows, $request->objects)),
            $request->includeReplication ? $this->replication($session, $skips) : [],
            $skips,
        );
    }

    /**
     * Sessions and the visibility of the view, in ONE statement.
     *
     * The window counts are the point. Asked separately they would describe a different instant, and
     * the whole question here is whether the rows in THIS answer are masked — a second query could
     * be answered by a moment in which they were not.
     *
     * `now()` rather than `clock_timestamp()`, deliberately: inside the reading's transaction it is
     * fixed at transaction start, so every duration in one snapshot is measured against one instant.
     * Two sessions that began together cannot come back with durations that differ by the time the
     * query took.
     *
     * The `query` column is not selected. It is the field that carries literals — an address, a
     * token, a customer name — into a report and into whatever log that report is pasted into.
     */
    private function activityQuery(): string
    {
        return <<<'SQL'
            select pid,
                   state,
                   coalesce(state, '') <> '' as state_visible,
                   round(extract(epoch from (now() - coalesce(xact_start, query_start))) * 1000) as running_for_ms,
                   count(*) over () as total_rows,
                   count(state) over () as visible_states
              from pg_stat_activity
             where pid <> pg_backend_pid()
               -- `backend_type` is itself masked for foreign sessions without pg_monitor — measured:
               -- 0 of 8 rows carry it. Filtering on it alone would throw away exactly the rows the
               -- masking check exists to count, so the detector would be defeated by the masking it
               -- detects and would report a masked view as a complete one. A null value is kept and
               -- counted; only a row the server NAMED as something else is excluded.
               and (backend_type is null or backend_type = 'client backend')
               and (
                     coalesce(xact_start, query_start) is null
                     or extract(epoch from (now() - coalesce(xact_start, query_start))) * 1000 >= ?
                   )
            SQL;
    }

    /**
     * Who is waiting on what, and who holds it.
     *
     * `pg_blocking_pids()` rather than a self-join on `pg_locks`, because the blocker of a waiting
     * lock is not always the obvious row: PostgreSQL resolves the whole conflict graph, including
     * locks held on other objects in the same transaction. A hand-rolled join gets the simple case
     * right and reports nobody for the interesting one.
     *
     * `not granted` is what makes this a WAIT rather than an inventory. A server has thousands of
     * granted locks at any moment — measured: 3832 on an idle test instance — and reporting them
     * would bury the handful that mean something.
     */
    private function lockQuery(): string
    {
        return <<<'SQL'
            select w.pid as waiter,
                   blocker.pid as holder,
                   w.mode as raw_mode,
                   coalesce(n.nspname || '.' || c.relname, 'unknown') as relation,
                   -- How long this request has been queued. `waitstart` is set when the wait BEGINS
                   -- and is null for a lock granted immediately, so a null here is "not waiting yet"
                   -- rather than "waiting for an unknown time" -- and the rows below are all waiters
                   -- by construction, so in practice it is the brief window before the server
                   -- records the start.
                   round(extract(epoch from (now() - w.waitstart)) * 1000) as waiting_for_ms
              from pg_locks w
              left join pg_class c on c.oid = w.relation
              left join pg_namespace n on n.oid = c.relnamespace
              left join lateral unnest(pg_blocking_pids(w.pid)) as blocker(pid) on true
             where not w.granted
            SQL;
    }

    /**
     * The masking check, and the single most important line in this class.
     *
     * Without it every arm of this reader is honest and the reading as a whole is a lie: the long
     * runners come back empty because the durations were null, and an empty list of long runners is
     * what a healthy server produces.
     *
     * @param  list<mixed>  $rows
     * @param  list<CatalogSkip>  $skips
     */
    private function recordMasking(array $rows, array &$skips): void
    {
        $first = $rows[0] ?? null;

        if (! is_object($first)) {
            return;
        }

        $total = (int) ($this->number($first, 'total_rows') ?? 0);
        $visible = (int) ($this->number($first, 'visible_states') ?? 0);

        if ($total <= $visible) {
            return;
        }

        $skips[] = CatalogSkip::for(
            SchemaObjectType::Setting,
            'pg_stat_activity',
            SkipReason::InsufficientPrivilege,
            sprintf(
                'the server listed %d sessions and withheld the state of %d of them — this role is '
                .'not a member of pg_monitor, so foreign sessions come back with their durations and '
                .'wait events null. The view did not refuse; it answered with the rows present and '
                .'the columns empty, which is why this is reported rather than filtered away.',
                $total,
                $total - $visible,
            ),
        );
    }

    /**
     * Which of the focus relations each session currently HOLDS a lock on.
     *
     * Deliberately the opposite filter from {@see self::lockQuery()}: that one reports `not granted`
     * because a server has thousands of granted locks at any moment and listing them would bury the
     * handful that mean something. Here the bound is the FOCUS SET instead — the deploy's own target
     * tables, never the server — so the same view answers a much narrower question: who is sitting on
     * the tables this migration is about to alter.
     *
     * That case is invisible to the wait query by construction. An `idle in transaction` holding
     * ACCESS EXCLUSIVE on the target is not WAITING for anything, so it appears in no `not granted`
     * row — and it is the single commonest way a deploy stalls.
     *
     * @param  list<mixed>  $rows
     * @param  list<string>  $objects  the focus set, so the answer speaks the caller's vocabulary
     * @return array<string, string> pid => the first focus relation it holds, in a stable order
     */
    private function heldRelations(array $rows, array $objects = []): array
    {
        $held = [];

        foreach ($rows as $row) {
            if (! is_object($row)) {
                continue;
            }

            $pid = $this->text($row, 'pid');
            // Reported in the CALLER'S vocabulary, not the catalog's. The focus set is what the
            // check will compare against, and it holds whatever the migration wrote — a bare
            // `users` for the ordinary `Schema::table('users', …)`. Handing back the composed
            // `public.users` there would find the lock and then fail to match it, which is the same
            // silence one step further along.
            $qualified = $this->text($row, 'relation');
            $bare = $this->text($row, 'bare_relation');

            $relation = in_array($qualified, $objects, true)
                ? $qualified
                : (in_array($bare, $objects, true) ? $bare : $qualified);

            // First wins, and the query orders by relation so "first" is the same on every run. A
            // session sitting on two of the deploy's tables produces one finding naming one of them:
            // the deploy is blocked either way, and the check's job is to say so, not to enumerate.
            if ($pid !== '' && $relation !== '' && ! isset($held[$pid])) {
                $held[$pid] = $relation;
            }
        }

        return $held;
    }

    /**
     * Granted locks on named relations only — the focus set is bound into the WHERE clause rather
     * than filtered afterwards, so an instance with thousands of locks still answers with at most
     * one row per session per target table.
     *
     * ## Why it matches TWO ways, and why that is not belt-and-braces
     *
     * A canonical target keeps the qualification the SOURCE wrote, and `Schema::table('users', …)`
     * writes none — so the target is the bare `users`. Comparing that against the composed catalog
     * name alone matched nothing for an ordinary Laravel migration, and the branch it feeds went
     * quiet on a server that really was holding the table. Measured against a real held lock: the
     * qualified target reported the blocker, the bare one reported nothing.
     *
     * Every object is offered to both comparisons rather than classified first, because the two
     * cannot collide — a qualified `public.users` never equals a bare `relname`, and a bare `users`
     * never equals the composed name. So nothing has to guess which form it was handed, and a table
     * whose name contains a literal dot stays safe.
     *
     * `pg_table_is_visible()` is what makes the bare arm honest: it asks the server whether an
     * UNQUALIFIED reference would find this table, which is `search_path` resolved by the thing that
     * owns it. `search_path` is a LIST, so appending a guessed `public.` would have been exactly the
     * assumption this package refuses.
     */
    private function heldRelationQuery(int $objectCount): string
    {
        return <<<SQL
            select l.pid as pid,
                   n.nspname || '.' || c.relname as relation,
                   c.relname as bare_relation
              from pg_locks l
              join pg_class c on c.oid = l.relation
              join pg_namespace n on n.oid = c.relnamespace
             where l.granted
               and l.pid is not null
               and l.pid <> pg_backend_pid()
               and (
                     n.nspname || '.' || c.relname in ({$this->placeholders($objectCount)})
                  or (c.relname in ({$this->placeholders($objectCount)}) and pg_table_is_visible(c.oid))
                   )
             order by l.pid, relation
            SQL;
    }

    /** `?, ?, …` for a bound IN list — the values are parameters, never interpolated. */
    private function placeholders(int $count): string
    {
        return implode(', ', array_fill(0, $count, '?'));
    }

    /**
     * @param  list<mixed>  $rows
     * @param  array<string, string>  $held  pid => the focus relation it is sitting on
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
            // A row whose duration is null is a MASKED row, not a short-lived one. It is not reported
            // as a long runner — there is no duration to report — and `recordMasking()` has already
            // made the reading partial because of it.
            if ($duration === null) {
                continue;
            }

            // Only the duration is checked, and the state deliberately is not. Measured on a role
            // without pg_monitor: `state`, `xact_start`, `query_start` and `wait_event_type` are
            // withheld TOGETHER — 0 of 8 foreign rows carried any of them. So a row with a duration
            // and no state cannot occur, and a second guard for it would be a branch that can never
            // fire: not a safety net, just a line nothing can reach.
            $pid = $this->text($row, 'pid');

            $sessions[] = new LongRunningSession(
                'pid='.$pid,
                (int) $duration,
                $state,
                $held[$pid] ?? null,
            );
        }

        return $sessions;
    }

    /**
     * @param  list<mixed>  $rows
     * @return list<LockWait>
     */
    private function lockWaits(array $rows): array
    {
        $waits = [];

        foreach ($rows as $row) {
            if (! is_object($row)) {
                continue;
            }

            $rawMode = $this->text($row, 'raw_mode');
            $holder = $this->text($row, 'holder');

            // The mapping that must not drop a row. A mode absent from the table arrives as null
            // beside the server's own spelling, and `ActivitySnapshot` turns that into a named skip
            // on its own — so an unfamiliar lock is MORE visible than a familiar one, not less.
            $waitingForMs = $this->number($row, 'waiting_for_ms');

            $waits[] = new LockWait(
                'pid='.$this->text($row, 'waiter'),
                $holder === '' ? null : 'pid='.$holder,
                $this->text($row, 'relation'),
                self::LOCK_MODES[$rawMode] ?? null,
                $rawMode,
                $waitingForMs === null ? null : (int) $waitingForMs,
            );
        }

        return $waits;
    }

    /**
     * How far the replicas are behind — asked only where the question has a subject.
     *
     * A standby has no `pg_stat_replication` rows of its own to give, so asking there would produce
     * an empty list that reads as "no lag". The role is established first and reported as a skip,
     * which is the difference between "the replicas are caught up" and "this is not the instance
     * that would know".
     *
     * @param  list<CatalogSkip>  $skips
     * @return list<ReplicationState>
     */
    #[RawSql(reason: 'reads pg_stat_replication and pg_replication_slots -- server views that exist for exactly this question')]
    private function replication(ReaderSession $session, array &$skips): array
    {
        $before = count($skips);

        $rows = DatabaseErrorTranslator::attemptBounded(
            fn (): array => array_values($session->read(
                fn (Connection $db): array => $db->select(
                    'select pg_is_in_recovery() as in_recovery, application_name, state,'
                    ."  coalesce(round(extract(epoch from replay_lag) * 1000), null) as lag_ms,\n"
                    // The same distance in BYTES, which answers a different question: `replay_lag`
                    // is how long ago the replica was current, and on a quiet primary it stays small
                    // no matter how much WAL is outstanding. The byte figure says how much is left
                    // to ship, and it is what a heavy migration is about to add to.
                    //
                    // From `pg_current_wal_lsn()`, NOT from `sent_lsn`. The first version measured
                    // `sent_lsn - replay_lsn`, which is the APPLY lag only — the gap between what
                    // the primary has already sent and what the replica has applied. Everything the
                    // primary has not sent yet is missing from it, and on the case that matters most
                    // that is nearly all of it: a replica whose connection dropped has a FROZEN
                    // `sent_lsn`, so the reported figure stops growing while the real backlog does
                    // not. The number would have looked reassuring exactly when it should not.
                    .'  pg_current_wal_lsn() - replay_lsn as lag_bytes'
                    .' from pg_stat_replication'
                    .' right join (select 1) as always on true',
                ),
            )),
            SchemaObjectType::Setting,
            'pg_stat_replication',
            $session,
            $skips,
        );

        $states = [];

        foreach ($rows as $row) {
            if (! is_object($row)) {
                continue;
            }

            if ($this->text($row, 'in_recovery') === '1' || $this->text($row, 'in_recovery') === 'true') {
                $skips[] = CatalogSkip::for(
                    SchemaObjectType::Setting,
                    'pg_stat_replication',
                    SkipReason::NotReadable,
                    'this connection reached a standby, which has no view of the replicas a primary '
                    .'streams to. Replication lag is a question for the primary, and an empty answer '
                    .'here would read as "the replicas are caught up" rather than as "wrong instance".',
                );

                return [];
            }

            $name = $this->text($row, 'application_name');

            if ($name === '') {
                continue;
            }

            $lagMs = $this->number($row, 'lag_ms');
            $lagBytes = $this->number($row, 'lag_bytes');

            $states[] = new ReplicationState(
                $name,
                $this->text($row, 'state'),
                lagBytes: $lagBytes === null ? null : (int) $lagBytes,
                lagMs: $lagMs === null ? null : (int) $lagMs,
            );
        }

        // A primary nobody streams from answers with no rows, and that is a COMPLETE answer rather
        // than a gap — which is exactly why it needs saying. Left bare, an empty list is what a
        // consumer asking "is a replica lagging?" reads as "no, they are fine", and the two are not
        // the same sentence: one means the replicas are caught up, the other that there are none.
        //
        // Only when the read produced nothing AND nothing was recorded about it. A refusal above
        // already carries its own reason, and a second one would say the same absence twice.
        if ($states === [] && count($skips) === $before) {
            $skips[] = CatalogSkip::for(
                SchemaObjectType::Setting,
                'pg_stat_replication',
                SkipReason::NotReadable,
                'no replica is streaming from this instance, so there is no lag to report. '
                .'PostgreSQL answers replication from the PRIMARY\'s side, so an empty result here '
                .'means "nobody is replicating from me" rather than "the replicas are caught up" — '
                .'and the two would otherwise read alike.',
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
