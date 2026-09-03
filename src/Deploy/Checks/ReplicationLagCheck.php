<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Checks;

use Pushery\SQLens\Catalog\Activity\ActivityRequest;
use Pushery\SQLens\Catalog\Activity\ReplicationState;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\ActivityReader;
use Pushery\SQLens\Contracts\PreflightCheck;
use Pushery\SQLens\Deploy\CheckResult;
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
 * How far behind the replicas are, immediately before a migration adds to their work.
 *
 * A schema change reaches a replica whenever it catches up. Until then an application reading from
 * replicas is running against the OLD schema — and the failures that produces during the window
 * (a column that does not exist yet) look like application bugs rather than like a deploy still in
 * progress. On a large table the window is minutes.
 *
 * ## Why a disconnected replica is its own finding
 *
 * Zero lag and no connection report the same number. One means caught up, the other means the
 * replica is not receiving anything at all — and the second is the more dangerous of the two,
 * because a deploy that "looked fine on the replicas" was measured against a replica that stopped
 * listening. The state is asked as a question about the CONNECTION rather than inferred from a lag
 * of zero, which is what {@see ReplicationState::isStreaming()} exists for.
 *
 * ## Why the threshold is a declared constant here
 *
 * The escalation-thresholds artefact keys on OPERATION classes and answers a different question:
 * how large an object must be before an existing finding is worth more attention. A replication lag
 * creates a finding rather than raising one, and it is measured in seconds rather than in rows or
 * bytes. Putting it there would mean one file answering two questions with one shape.
 *
 * @see https://www.postgresql.org/docs/18/monitoring-stats.html
 * @see https://dev.mysql.com/doc/refman/8.4/en/performance-schema-replication-tables.html
 */
final readonly class ReplicationLagCheck implements PreflightCheck
{
    public const string ID = 'DEPLOY.PREFLIGHT.REPLICATION_LAG';

    /**
     * When a lag stops being catch-up and becomes a stale read, in milliseconds.
     *
     * Declared here so it is arguable rather than buried. Ten seconds is the line because that is
     * roughly where a replica stops being "a moment behind" and starts serving a version of the
     * world a user would notice — and a migration lands on top of whatever is already queued.
     *
     * It is the DEFAULT and no longer the gate: `sqlens.preflight.replication_lag_ms` moves it, and
     * the run carries the value it judged with. A project whose replicas are legitimately seconds
     * behind reached for switching this check off, which took the real cases with it.
     */
    public const int DEFAULT_LAG_CEILING_MS = 10_000;

    public function id(): string
    {
        return self::ID;
    }

    public function appliesTo(string $driver): bool
    {
        return $driver === 'pgsql' || $driver === 'mysql';
    }

    public function run(PreflightContext $context): CheckResult
    {
        if (! $context->activity instanceof ActivityReader) {
            return CheckResult::undetermined(
                self::ID,
                'replication_views_unreadable: this run has no activity reader, so how far the '
                .'replicas are behind is unknown. That is not the same as them being caught up — '
                .'a deploy is about to add to whatever they already owe.',
            );
        }

        try {
            // `includeReplication: true`, and this ONE argument is the check.
            //
            // The reader's default is `false`, and that default is right for the reader: on an
            // instance with no replicas the view is a round trip spent to be told so, and most
            // callers are not asking about replication at all. But this check IS the caller that
            // asks — and building the request without the flag meant `$snapshot->replication` came
            // back empty on every real run, the early return below fired, and
            // `DEPLOY.PREFLIGHT.REPLICATION_LAG` could not be produced by any deploy against any
            // server. A replica that was not streaming at all — the more dangerous of the two
            // states this class exists for — was reported as a clean pass.
            //
            // Nothing was red, because the unit fake ignores the flag and hands back its list
            // regardless. The cost of the round trip is the price of the check existing.
            $snapshot = $context->activity->read(new ActivityRequest(includeReplication: true));
        } catch (Throwable $failure) {
            return CheckResult::undetermined(
                self::ID,
                'replication_views_unreadable: the replication views could not be read, so how far '
                .'the replicas are behind is unknown: '.$failure->getMessage(),
            );
        }

        // No replicas configured is a clean PASS **with a reason**, not a bare one.
        //
        // Bare, this return and the one at the bottom are byte-identical, and a reader cannot tell
        // "this instance has no replicas" from "the replicas are caught up". Those are two different
        // sentences about a deploy, and this package refuses to let them look alike. The pattern is
        // the one `ServerVersionSkewCheck` already uses: a pass may carry a finding.
        if ($snapshot->replication === []) {
            return CheckResult::pass(self::ID, [$this->noReplicationFinding($context)]);
        }

        $findings = [];

        foreach ($snapshot->replication as $replica) {
            $finding = $this->judge($context, $replica);

            if ($finding instanceof Finding) {
                $findings[] = $finding;
            }
        }

        return $findings === []
            ? CheckResult::pass(self::ID)
            : CheckResult::fail(self::ID, $findings);
    }

    /**
     * The named non-case: this instance streams to nobody.
     *
     * Reported rather than silent, and as a PASS rather than a finding that counts against the
     * deploy — a single-instance deployment is entirely legitimate. What it must not do is look
     * identical to "the replicas are fine", which is what a bare pass did.
     */
    private function noReplicationFinding(PreflightContext $context): Finding
    {
        return Finding::pass(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: 'no_replication_configured: this instance reports no replicas streaming from '
                .'it, so there is no lag for the deploy to add to. That is a statement about THIS '
                .'instance, not a clean bill of health for a cluster — a replica that is not '
                .'connected at all does not appear here either, and the connection state is what '
                .'the finding above would judge if there were one.',
            location: Location::inCatalog($context->driver, $context->connection, 'replication', SchemaObjectType::Setting),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::ID),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            severity: Severity::Info,
        )->withDowntimeClass(DowntimeClass::Online);
    }

    private function judge(PreflightContext $context, ReplicationState $replica): ?Finding
    {
        if (! $replica->isStreaming()) {
            return $this->finding(
                $context,
                $replica->replica,
                sprintf(
                    'The replica `%s` is not streaming — the server reports it as `%s`. It is not '
                    .'behind by a little; it is not receiving changes at all, and a lag of zero '
                    .'would say the same thing. Anything this deploy does reaches it whenever it '
                    .'reconnects, which may be after somebody has already read the old schema '
                    .'through it and filed the result as a bug.',
                    $replica->replica,
                    $replica->state,
                ),
                Severity::High,
            );
        }

        if ($replica->lagMs === null || $replica->lagMs <= $context->replicationLagMs) {
            return null;
        }

        return $this->finding(
            $context,
            $replica->replica,
            sprintf(
                'The replica `%s` is %.1F s behind, past the %.1F s this run judged against, and '
                .'a migration is about to add to what it already owes. Until it catches up, anything '
                .'reading through it sees the OLD schema — and a missing column during that window '
                .'looks like an application bug rather than like a deploy still in progress. Move '
                .'the line with sqlens.preflight.replication_lag_ms if this is normal here.',
                $replica->replica,
                $replica->lagMs / 1000,
                $context->replicationLagMs / 1000,
            ),
            // High rather than critical: a lagging replica is a stale read, not a broken write, and
            // the primary this deploy targets is unaffected. A replica that is not connected at all
            // gets the same severity for the opposite reason — there, nothing is catching up.
            Severity::High,
        );
    }

    private function finding(PreflightContext $context, string $replica, string $message, Severity $severity): Finding
    {
        return Finding::fail(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: $message,
            location: Location::inCatalog($context->driver, $context->connection, $replica, SchemaObjectType::Setting),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::ID),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            severity: $severity,
        )->withDowntimeClass(
            // `online`: the lag costs nobody a lock and delays no statement. What it costs is the
            // truth of what a replica serves, and calling that `blocking` would teach a reader to
            // discount the field.
            DowntimeClass::Online,
        );
    }
}
