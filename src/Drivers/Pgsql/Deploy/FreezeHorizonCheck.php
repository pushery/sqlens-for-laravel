<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Deploy;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Capture\CapturedStatement;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PreflightCheck;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\DeployNotice;
use Pushery\SQLens\Deploy\PreflightContext;
use Pushery\SQLens\Findings\CredentialRedactor;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;
use Throwable;

/**
 * A table close enough to its freeze horizon that an anti-wraparound vacuum will stand in the way.
 *
 * ## Why this is a DEPLOY question and not a monitoring one
 *
 * An ordinary autovacuum YIELDS: ask for a conflicting lock and it cancels itself, and the `ALTER
 * TABLE` behind it proceeds. **An autovacuum running to prevent wraparound does not.** It holds its
 * lock to the end, because the alternative is a cluster that stops accepting writes. On a large
 * table that is hours, and from the outside it looks like a lock nobody holds: `pg_locks` shows the
 * waiter, the holder is a background worker, and the deploy simply does not move.
 *
 * "Can this DDL run right now" is the question the preflight exists to answer, and the freeze
 * horizon is one of the few answers to it that the instance can give in advance.
 *
 * ## TWO clocks, and the second one is the one nobody watches
 *
 * PostgreSQL counts two horizons, and either one stops the cluster when it runs out:
 *
 * - **Transaction ids**, consumed by writing. `age(relfrozenxid)` against `autovacuum_freeze_max_age`.
 * - **Multixacts**, consumed by LOCKING. A multixact is created as soon as more than one transaction
 *   locks the same row, which is the ordinary state of a foreign-key check and of every
 *   an explicit row lock taken in a `SELECT`. `mxid_age(relminmxid)` against
 *   `autovacuum_multixact_freeze_max_age`.
 *
 * A lock-heavy table can be spotless on the first clock and be the table that stops the cluster. The
 * two have separate thresholds and are advanced separately, so this check reads both and reports
 * whichever is closer.
 *
 * ## The thresholds come from the SERVER
 *
 * `autovacuum_freeze_max_age` is tunable and frequently tuned — a busy instance raises it, a managed
 * provider may ship its own default. A check holding an age against a hard-coded 200 million would
 * be wrong in both directions on such an instance, quietly. `current_setting()` asks.
 *
 * ⚠️ What it does NOT read is a per-table `reloptions` override. A table can carry its own
 * `autovacuum_freeze_max_age`, and this check would then compare against the cluster's. The finding
 * says so rather than pretending otherwise: it is the direction that OVER-reports, which here costs
 * a sentence in a report rather than a deploy standing in a queue nobody can see.
 *
 * ## Why a running vacuum is never "cancel it"
 *
 * `pg_cancel_backend()` on an anti-wraparound worker buys nothing: the launcher starts it again
 * within `autovacuum_naptime`, and the horizon is closer than it was. Worse, every cancellation
 * throws away the work already done. So the finding NAMES it, reports its progress from
 * `pg_stat_progress_vacuum`, and says to wait — which is the advice that is actually cheaper.
 *
 * @see https://www.postgresql.org/docs/18/routine-vacuuming.html
 */
final readonly class FreezeHorizonCheck implements PreflightCheck
{
    public const string ID = 'DEPLOY.PREFLIGHT.FREEZE_HORIZON';

    /**
     * The statement kinds that take a lock an anti-wraparound worker will not yield to.
     *
     * The same set the lock-blocker check reasons about, and for the same reason: a statement that
     * takes nothing stronger than `SHARE UPDATE EXCLUSIVE` runs beside a vacuum rather than behind
     * it, so reporting it here would put a finding in front of a deploy that is not affected.
     *
     * @var list<StatementKind>
     */
    private const array EXCLUSIVE_KINDS = [
        StatementKind::AlterTable,
        StatementKind::DropTable,
        StatementKind::TruncateTable,
        StatementKind::AddColumn,
        StatementKind::AlterColumn,
        StatementKind::DropColumn,
        StatementKind::AddConstraint,
        StatementKind::AddPrimaryKey,
        StatementKind::AddForeignKey,
        StatementKind::DropConstraint,
        StatementKind::Rename,
    ];

    /** Report from here: at the threshold the launcher starts an anti-wraparound worker. */
    private const float AT_THRESHOLD = 1.0;

    /** …and from here, because it will start during a window of any length. */
    private const float NEAR_THRESHOLD = 0.9;

    public function id(): string
    {
        return self::ID;
    }

    public function appliesTo(string $driver): bool
    {
        // PostgreSQL only, and the reason is that InnoDB has no visible freeze horizon rather than
        // that nobody wrote the MySQL half. Its counterpart is purge lag, which is a different
        // measurement against a different failure, and whether that earns a check of its own is its
        // own question.
        return $driver === 'pgsql';
    }

    public function run(PreflightContext $context): CheckResult
    {
        // Nothing pending is the honest pass: this check is about the tables a run is ABOUT to lock,
        // and a deploy with no statements locks nothing.
        if ($context->pending->isEmpty()) {
            return CheckResult::pass(self::ID);
        }

        $targets = $this->exclusiveTargets($context);

        if ($targets === []) {
            return CheckResult::pass(self::ID);
        }

        try {
            $ages = $this->ages($context, $targets);
            $running = $this->runningAntiWraparound($context);
        } catch (Throwable $failure) {
            return CheckResult::undetermined(
                self::ID,
                UndeterminedReason::FreezeHorizonUnreadable,
                'how close these tables are to their freeze horizon is '
                .'unknown, so whether an anti-wraparound vacuum will stand in front of this deploy '
                .'cannot be said. A managed database commonly withholds these views: '
                .new CredentialRedactor()->redact($failure->getMessage()),
            );
        }

        $findings = [];

        foreach ($ages as $row) {
            $finding = $this->findingFor($context, $row, $running, $this->rewritesAnything($context));

            if ($finding instanceof Finding) {
                $findings[] = $finding;
            }
        }

        if ($findings !== []) {
            // The age axis answered, and it answered with something. That is a verdict about these
            // tables whether or not a vacuum is visible, so it is reported as one — the check does
            // not become undetermined because half of it was masked. {@see self::message()} carries
            // the caveat into the finding itself.
            return CheckResult::fail(self::ID, $findings);
        }

        // Asked only HERE, and only now: the answer can change nothing while there are findings, and
        // a query bought for an answer nobody reads is a query on somebody's production instance at
        // the moment before a deploy.
        try {
            $vacuumVisible = $this->seesForeignSessions($context);
        } catch (Throwable $failure) {
            return CheckResult::undetermined(
                self::ID,
                UndeterminedReason::FreezeHorizonUnreadable,
                'whether this role can see other sessions could not be established, so an empty '
                .'vacuum reading cannot be read as "none running": '
                .new CredentialRedactor()->redact($failure->getMessage()),
            );
        }

        // ⚠️ NOTHING FOUND IS ONLY A PASS IF BOTH AXES ANSWERED. The age axis reads `pg_class` and
        // is readable by anyone; the vacuum axis reads `pg_stat_activity`, which MASKS foreign rows
        // for a role without `pg_read_all_stats` rather than refusing them — so it comes back empty,
        // without an error, and "no anti-wraparound vacuum is running" cannot be told from "I may
        // not see one". Reporting a pass there is the silent null this package refuses everywhere,
        // here in a deploy gate.
        return $vacuumVisible
            ? CheckResult::pass(self::ID)
            : CheckResult::undetermined(
                self::ID,
                UndeterminedReason::VacuumActivityNotVisible,
                'none of the tables this deploy locks is near its freeze horizon, and that half is '
                .'answered. Whether an anti-wraparound autovacuum is ALREADY running on one of them '
                .'is not: this role does not hold pg_read_all_stats, so PostgreSQL masks other '
                .'sessions in pg_stat_activity and the reading comes back empty rather than '
                .'refused. Grant pg_read_all_stats to the role this check runs as, or read the '
                .'result as "the age clocks are fine, the vacuum question was not asked".',
            );
    }

    /**
     * Both clocks for the tables this run will lock, against the thresholds the SERVER carries.
     *
     * @param  list<string>  $targets
     * @return list<object>
     */
    #[RawSql(reason: 'reads pg_class and current_setting for both freeze clocks; an age and a cluster threshold are server facts with no model equivalent')]
    private function ages(PreflightContext $context, array $targets): array
    {
        $placeholders = implode(', ', array_fill(0, count($targets), '?'));

        $rows = $context->session->read(static fn (Connection $db): array => $db->select(
            'select n.nspname || \'.\' || c.relname as relation,'
            .' age(c.relfrozenxid) as xid_age,'
            // `mxid_age` rather than `age` on relminmxid: multixact ids live in their own counter,
            // and `age()` would measure them against the transaction one. The two are unrelated
            // numbers that both look like plausible ages.
            .' mxid_age(c.relminmxid) as mxid_age,'
            .' pg_catalog.current_setting(\'autovacuum_freeze_max_age\')::bigint as xid_threshold,'
            .' pg_catalog.current_setting(\'autovacuum_multixact_freeze_max_age\')::bigint as mxid_threshold'
            .' from pg_class c'
            .' join pg_namespace n on n.oid = c.relnamespace'
            // Ordinary tables, partitioned parents and materialized views. A partitioned PARENT has
            // no storage and therefore no horizon of its own, and it is kept in deliberately: the
            // row comes back with a zero age rather than missing, which is the answer, while
            // dropping it here would make "not near the horizon" and "not examined" identical.
            .' where c.relkind in (\'r\', \'m\', \'p\')'
            .' and n.nspname || \'.\' || c.relname in ('.$placeholders.')'
            .' order by relation',
            $targets,
        ));

        return array_values(array_map(static fn (mixed $row): object => (object) $row, $rows));
    }

    /**
     * Whether this role sees OTHER sessions in `pg_stat_activity` — the question an empty reading
     * from {@see self::runningAntiWraparound()} cannot answer for itself.
     *
     * ⚠️ `pg_has_role` ON `pg_read_all_stats`, DELIBERATELY NOT `has_table_privilege` ON THE VIEW.
     * The view is readable by PUBLIC, which is exactly why nothing throws: PostgreSQL masks foreign
     * rows instead of refusing them. So the question is not "may I read it" — I may — but "do
     * foreign sessions appear in what I read".
     *
     * Measured on 18.4 with a role holding only CONNECT: two foreign sessions present, both with
     * `query` reading `<insufficient privilege>`, and the vacuum filter matching none of them. No
     * exception anywhere on that path.
     *
     * A superuser answers true through role membership, so the check does not need a second arm
     * for it.
     */
    #[RawSql(reason: 'asks pg_has_role about pg_read_all_stats; whether this role sees foreign sessions is a server fact with no model equivalent')]
    private function seesForeignSessions(PreflightContext $context): bool
    {
        $row = $context->session->read(static fn (Connection $db): array => $db->select(
            "select pg_catalog.pg_has_role(current_user, 'pg_read_all_stats', 'USAGE') as visible",
        ));

        return ($row[0] ?? null) !== null && (bool) ((array) $row[0])['visible'];
    }

    /**
     * The anti-wraparound vacuums running right now, by relation.
     *
     * Recognized from the worker's own `query` text, which is how PostgreSQL says it: an autovacuum
     * running for this reason appends `(to prevent wraparound)`. There is no column for it — the
     * progress view reports the phase and the blocks, not why the vacuum started.
     *
     * @return array<string, object> relation => its progress row
     */
    #[RawSql(reason: 'reads pg_stat_progress_vacuum joined to pg_stat_activity; a running autovacuum and its progress are server facts with no model equivalent')]
    private function runningAntiWraparound(PreflightContext $context): array
    {
        $rows = $context->session->read(static fn (Connection $db): array => $db->select(
            'select p.relid::regclass::text as relation, p.phase,'
            .' p.heap_blks_scanned, p.heap_blks_total'
            .' from pg_stat_progress_vacuum p'
            .' join pg_stat_activity a on a.pid = p.pid'
            .' where a.query like \'autovacuum:%to prevent wraparound%\'',
        ));

        $byRelation = [];

        foreach ($rows as $row) {
            $relation = $this->text((object) $row, 'relation');

            if ($relation !== '') {
                $byRelation[$relation] = (object) $row;
            }
        }

        return $byRelation;
    }

    /**
     * The finding for one table, or null when neither clock is close enough to matter.
     *
     * @param  array<string, object>  $running
     */
    private function findingFor(PreflightContext $context, object $row, array $running, bool $rewrites): ?Finding
    {
        $relation = $this->text($row, 'relation');
        $xidAge = $this->number($row, 'xid_age') ?? 0;
        $mxidAge = $this->number($row, 'mxid_age') ?? 0;
        $xidThreshold = $this->number($row, 'xid_threshold') ?? 0;
        $mxidThreshold = $this->number($row, 'mxid_threshold') ?? 0;

        $xidRatio = $xidThreshold > 0 ? $xidAge / $xidThreshold : 0.0;
        $mxidRatio = $mxidThreshold > 0 ? $mxidAge / $mxidThreshold : 0.0;

        // Whichever clock is closer decides, because either one alone starts the worker.
        $onMultixact = $mxidRatio > $xidRatio;
        $ratio = max($xidRatio, $mxidRatio);
        $vacuum = $running[$relation] ?? null;

        if ($ratio < self::NEAR_THRESHOLD && $vacuum === null) {
            return null;
        }

        return Finding::fail(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: $this->message($relation, $onMultixact, $xidAge, $mxidAge, $xidThreshold, $mxidThreshold, $ratio, $vacuum, $rewrites),
            location: Location::inCatalog($context->driver, $context->connection, $relation, SchemaObjectType::Table),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::ID),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            severity: $vacuum !== null || $ratio >= self::AT_THRESHOLD ? Severity::High : Severity::Medium,
        )->withDowntimeClass(
            // `blocking`, and it is the accurate word rather than the alarming one: the statement
            // this deploy runs will WAIT, holding its own lock request in the queue, and every
            // reader that arrives behind it waits too.
            DowntimeClass::Blocking,
        );
    }

    /** The sentence a reader acts on — what is close, on which clock, and what to do about it. */
    private function message(
        string $relation,
        bool $onMultixact,
        int $xidAge,
        int $mxidAge,
        int $xidThreshold,
        int $mxidThreshold,
        float $ratio,
        ?object $vacuum,
        bool $rewrites,
    ): string {
        $clock = $onMultixact
            ? sprintf(
                'Its MULTIXACT age is %s against a threshold of %s. Multixacts are consumed by '
                .'LOCKING rather than by writing — one is created as soon as a second transaction '
                .'locks a row somebody else already holds, which is the ordinary state of a '
                .'foreign-key check and of every explicit row lock taken in a SELECT. This is the '
                .'clock that runs '
                .'out on a table whose transaction age looks fine.',
                number_format($mxidAge),
                number_format($mxidThreshold),
            )
            : sprintf(
                'Its transaction age is %s against a threshold of %s.',
                number_format($xidAge),
                number_format($xidThreshold),
            );

        $state = $this->state($ratio, $vacuum);
        $rewriteNote = $rewrites ? $this->rewriteNote() : '';

        return sprintf(
            'The deploy takes an ACCESS EXCLUSIVE lock on `%s`, and that table is near its freeze '
            .'horizon. %s %s An ordinary autovacuum yields to a conflicting lock request; one '
            .'running to prevent wraparound does NOT — it holds its lock to the end, and the ALTER '
            .'waits behind it, looking from the outside like a lock nobody holds.%s '
            .'The thresholds above are the cluster\'s; a per-table reloptions override is not read '
            .'here, so a table that carries its own is reported against the wider setting.',
            $relation,
            $clock,
            $state,
            $rewriteNote,
        );
    }

    /** Where this table stands right now — a worker on it, at the line, or close to it. */
    private function state(float $ratio, ?object $vacuum): string
    {
        if ($vacuum !== null) {
            return sprintf(
                'An anti-wraparound autovacuum is running on it RIGHT NOW (%s%s). Do not cancel it: '
                .'the launcher starts it again within autovacuum_naptime, the work already done is '
                .'thrown away, and the horizon is closer than before. Wait for it, or move the '
                .'deploy.',
                $this->phaseOf($vacuum),
                $this->progress($vacuum),
            );
        }

        if ($ratio >= self::AT_THRESHOLD) {
            return 'It is AT or past the threshold, so the launcher will start an anti-wraparound '
                .'autovacuum on it — possibly while this deploy is running.';
        }

        return 'It is close enough that an anti-wraparound autovacuum can start during this deploy '
            .'window.';
    }

    /** The worker's phase, or the honest absence of one — the view does not always carry it. */
    private function phaseOf(object $vacuum): string
    {
        $phase = $this->text($vacuum, 'phase');

        return $phase === '' ? 'phase not reported' : 'phase '.$phase;
    }

    /** Why a rewrite lengthens the window rather than shortening it. */
    private function rewriteNote(): string
    {
        return ' This run rewrites a table, which makes the window LONGER rather than shorter: the '
            .'lock is held for the whole rewrite, and a vacuum that arrives during it waits, and so '
            .'does everything behind the vacuum.';
    }

    /** How far the running vacuum has got, when the view says. */
    private function progress(object $vacuum): string
    {
        $scanned = $this->number($vacuum, 'heap_blks_scanned');
        $total = $this->number($vacuum, 'heap_blks_total');

        if ($scanned === null || $total === null || $total <= 0) {
            return '';
        }

        return sprintf(', %s of %s blocks scanned', number_format($scanned), number_format($total));
    }

    /**
     * The relations this run will take ACCESS EXCLUSIVE on.
     *
     * Read from the statements' own `targets`, which the capture already resolved — parsing the SQL
     * here would be a second classification free to disagree with the one the report is built on.
     *
     * @return list<string>
     */
    private function exclusiveTargets(PreflightContext $context): array
    {
        $targets = [];

        foreach ($context->pending->statements as $statement) {
            if (! in_array($statement->statementKind, self::EXCLUSIVE_KINDS, true)) {
                continue;
            }

            foreach ($statement->targets ?? [] as $target) {
                if ($target->type !== SchemaObjectType::Table || ! $target->isSubject()) {
                    continue;
                }

                // The QUALIFIED name: pg_class is joined to pg_namespace here, and a bare name would
                // match every schema on a server that has several.
                $targets[] = $target->qualifiedName();
            }
        }

        return array_values(array_unique($targets));
    }

    /** Whether anything in this run rewrites a table, which lengthens the window rather than shortening it. */
    private function rewritesAnything(PreflightContext $context): bool
    {
        return array_any(
            $context->pending->statements,
            static fn (CapturedStatement $statement): bool => $statement->statementKind === StatementKind::AlterColumn,
        );
    }

    private function text(object $row, string $key): string
    {
        $value = $row->{$key} ?? null;

        return is_scalar($value) ? (string) $value : '';
    }

    private function number(object $row, string $key): ?int
    {
        $value = $row->{$key} ?? null;

        return is_numeric($value) ? (int) $value : null;
    }
}
