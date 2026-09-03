<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Deploy;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PreflightCheck;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\Checks\DiskHeadroomCheck;
use Pushery\SQLens\Deploy\DeployNotice;
use Pushery\SQLens\Deploy\PreflightContext;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;
use Throwable;

/**
 * A replication slot nobody is reading from, holding WAL the deploy is about to need room for.
 *
 * A slot is a promise: the primary keeps every WAL segment since the slot's `restart_lsn` until the
 * consumer confirms it. That is exactly right while somebody is consuming. When the consumer is
 * gone — a replica retired, a CDC connector switched off, a logical subscriber that failed and was
 * never cleaned up — the promise stands and the segments accumulate. Nothing errors. The disk fills.
 *
 * ## Why a deploy is the moment to say so
 *
 * A migration that rewrites a table needs room for a second copy of it while the rewrite runs, and
 * every rewrite generates WAL in proportion to what it touches. A retained slot has already spent
 * some of the headroom that rewrite is about to ask for, and it is the one cause of a full disk that
 * the instance can NAME.
 *
 * That last part is why this check is worth its query. {@see DiskHeadroomCheck}
 * reports `undetermined` on a managed database because free capacity is not something the server
 * exposes — so on exactly the instances most projects run, "will this fit" has no answer. A retained
 * slot is visible from inside the database, and it is the commonest reason the answer would have
 * been no.
 *
 * ## `wal_status` is the finding, not `active`
 *
 * An inactive slot is not automatically a problem: a fresh one reserves nothing until its consumer
 * connects, and a replica that reconnects every few minutes is inactive between times. What matters
 * is how much is being held and whether the server still considers it safe:
 *
 * - `reserved` — within `max_slot_wal_keep_size`, or unbounded because none is set.
 * - `extended` — past the configured limit; the segments are kept anyway, for now.
 * - `unreserved` — no longer guaranteed; the consumer must catch up or it will not be able to.
 * - `lost` — segments are gone. The consumer cannot resume and must be rebuilt.
 *
 * `lost` is the one that reads as the least urgent and is the most final: the damage is done, and
 * the slot is now pure retention with nothing to show for it.
 *
 * ## What this never does
 *
 * It does not drop a slot. Dropping one detaches its consumer permanently — a replica that was
 * merely offline for maintenance cannot resume afterwards, and it has to be rebuilt from a base
 * backup. The finding names the slot and what it is holding; the decision belongs to whoever knows
 * what that consumer was.
 *
 * @see https://www.postgresql.org/docs/18/view-pg-replication-slots.html
 */
final readonly class ReplicationSlotCheck implements PreflightCheck
{
    public const string ID = 'DEPLOY.PREFLIGHT.INACTIVE_REPLICATION_SLOT';

    /**
     * What the server's own `wal_status` means for a deploy, in the order it degrades.
     *
     * Mapped rather than collapsed to "bad", because the four call for different actions. A
     * `reserved` slot is a housekeeping item; a `lost` one is a replica that has to be rebuilt, and
     * a report that spelled both "inactive replication slot" would have a reader treating the second
     * like the first.
     */
    private const array SEVERITY_BY_STATUS = [
        'reserved' => Severity::Low,
        'extended' => Severity::Medium,
        'unreserved' => Severity::High,
        'lost' => Severity::High,
    ];

    public function id(): string
    {
        return self::ID;
    }

    public function appliesTo(string $driver): bool
    {
        // PostgreSQL only, and MySQL has no counterpart to write rather than one left unwritten:
        // binary-log retention there is a time-or-size policy on the primary (`binlog_expire_logs_
        // seconds`), not a per-consumer reservation, so there is no object to name and no consumer
        // to hold responsible for it.
        return $driver === 'pgsql';
    }

    #[RawSql(reason: 'reads pg_replication_slots; a slot holding WAL is a server fact with no model equivalent')]
    public function run(PreflightContext $context): CheckResult
    {
        try {
            $rows = $context->session->read(static fn (Connection $db): array => $db->select(
                'select slot_name, slot_type, active, wal_status,'
                // `pg_current_wal_lsn() - restart_lsn` rather than `safe_wal_size`, deliberately.
                // `safe_wal_size` is null whenever `max_slot_wal_keep_size` is unset — which is the
                // DEFAULT, and the most dangerous configuration, because retention is then unbounded.
                // Reporting null there would leave the worst case as the one with no number.
                .' case when restart_lsn is null then null'
                .'      else pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) end as retained_bytes'
                .' from pg_replication_slots'
                // A slot that reserves nothing is holding nothing. A freshly created slot waiting for
                // its first consumer looks identical to a retired one on `active` alone, and only
                // `restart_lsn` tells them apart — so the distinction is made here rather than left
                // to a reader.
                .' where not active and restart_lsn is not null'
                .' order by slot_name',
            ));
        } catch (Throwable $failure) {
            return CheckResult::undetermined(
                self::ID,
                'replication_slots_unreadable: whether a retired consumer is holding WAL is unknown, '
                .'so how much of the headroom this migration needs has already been spent cannot be '
                .'said. A managed database commonly withholds this view: '.$failure->getMessage(),
            );
        }

        $findings = [];

        foreach (array_map(static fn (mixed $row): object => (object) $row, $rows) as $row) {
            $findings[] = $this->finding(
                $context,
                $this->text($row, 'slot_name'),
                $this->text($row, 'slot_type'),
                $this->text($row, 'wal_status'),
                $this->number($row, 'retained_bytes'),
            );
        }

        return $findings === []
            ? CheckResult::pass(self::ID)
            : CheckResult::fail(self::ID, $findings);
    }

    private function finding(
        PreflightContext $context,
        string $slot,
        string $type,
        string $walStatus,
        ?int $retainedBytes,
    ): Finding {
        return Finding::fail(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: sprintf(
                'The %s replication slot `%s` has no consumer connected and is holding %s of WAL '
                .'(wal_status: %s). %s A migration that rewrites a table needs room for a second copy '
                .'while it runs, and this slot has already spent some of it. SQLens does not drop the '
                .'slot: dropping one detaches its consumer permanently, and a replica that was merely '
                .'offline for maintenance would then need rebuilding from a base backup. Find out what '
                .'was reading from it, then either reconnect it or drop the slot deliberately.',
                $type === '' ? 'inactive' : $type,
                $slot,
                $retainedBytes === null ? 'an unreported amount' : $this->humanBytes($retainedBytes),
                $walStatus === '' ? 'not reported' : $walStatus,
                $this->statusSentence($walStatus),
            ),
            location: Location::inCatalog($context->driver, $context->connection, $slot, SchemaObjectType::Setting),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::ID),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            severity: self::SEVERITY_BY_STATUS[$walStatus] ?? Severity::Medium,
        )->withDowntimeClass(
            // `online`, and it is the honest answer rather than the flattering one: this finding is
            // about a STATE the instance is already in, not about a statement anybody will run.
            // Nothing here takes a lock or stops a read. What it costs is headroom, and that is the
            // severity axis rather than this one.
            DowntimeClass::Online,
        );
    }

    /** The sentence that turns the server's one-word status into what it means for this deploy. */
    private function statusSentence(string $walStatus): string
    {
        return match ($walStatus) {
            'reserved' => 'The segments are within the configured limit, or no limit is set at all — '
                .'which is the default, and means retention is unbounded.',
            'extended' => 'It is already past max_slot_wal_keep_size; the segments are being kept '
                .'anyway, for now.',
            'unreserved' => 'The segments are no longer guaranteed. The consumer has to catch up '
                .'soon or it will no longer be able to.',
            'lost' => 'The segments are GONE. Whatever was reading from this slot cannot resume and '
                .'has to be rebuilt — so the slot is now retention with nothing left to show for it.',
            default => 'This build does not know that wal_status, which is a gap in SQLens rather '
                .'than in your database — the slot and its size above still stand.',
        };
    }

    /** Bytes a human can hold against a disk, rather than a number with ten digits. */
    private function humanBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $value = (float) $bytes;
        $unit = 0;

        while ($value >= 1024 && $unit < count($units) - 1) {
            $value /= 1024;
            $unit++;
        }

        return sprintf($unit === 0 ? '%d %s' : '%.1F %s', $value, $units[$unit]);
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
