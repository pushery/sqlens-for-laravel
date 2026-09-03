<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Contracts\ActivityReader;
use Pushery\SQLens\Contracts\StatisticsReader;
use Pushery\SQLens\Rules\ServerVersion;

/**
 * Everything a preflight check is allowed to look at, handed to it rather than fetched by it.
 *
 * ## Why the checks receive this instead of reaching for what they need
 *
 * Three reasons, and none of them is tidiness.
 *
 * A check that opened its own connection would be a second session on the target database at the
 * one moment nobody wants extra load on it — and the promise "one connection per run" would stop
 * being checkable.
 *
 * A check that resolved the pending migrations itself would be a second code path beside
 * `sqlens:lint`, free to disagree with it about which migrations are pending and what they say.
 * Two answers to that question is how a CI result and a deploy result start diverging quietly.
 *
 * And the BUDGET has to be shared to mean anything. Each check receiving its own five seconds is a
 * gate with no bound at all; what bounds a run is one deadline that every check reads and spends
 * from.
 */
final readonly class PreflightContext
{
    /**
     * The shipped thresholds, named once.
     *
     * They appear in three places that must agree — this class's defaults, `config/sqlens.php`, and
     * the fallback `PreflightService` uses when a configured value is unusable. Three literals would
     * drift, and the drift would be invisible: a context built by hand in a test would simply behave
     * unlike a real run, which is the quietest kind of wrong.
     */
    public const int DEFAULT_LONG_RUNNING_MS = 5_000;

    public const int DEFAULT_REPLICATION_LAG_MS = 10_000;

    public function __construct(
        /** The Laravel connection name this run addresses — one instance, named in the report. */
        public string $connection,
        /** The driver key, so a check can answer `appliesTo()` without opening anything. */
        public string $driver,
        /** What the server actually IS, read from it rather than assumed from configuration. */
        public ServerVersion $serverVersion,
        /** The sealed read-only session every check reads through. */
        public ReaderSession $session,
        /** The pending migrations, canonicalized by the same engine `sqlens:lint` uses. */
        public PendingWork $pending,
        /** The profile this run declares — `predeploy` by default, and paranoid. */
        public string $profile,
        /** When the whole run must be finished, as a monotonic nanosecond reading. */
        private int $deadlineAt,
        /**
         * How big the objects a finding names are, or null when this driver has no reader for it.
         *
         * Resolved by the connection layer and handed down, never built by a check: building one
         * needs a `Connection`, and the console that assembles this context may name no database
         * class — the core-purity census pins exactly three files that know both engines, and the
         * console is not among them.
         */
        public ?StatisticsReader $statistics = null,
        /** What the instance is doing right now, or null when this driver has no reader for it. */
        public ?ActivityReader $activity = null,
        /**
         * The database ROLE the migrations run as, or null when the configuration does not say.
         *
         * The role rather than the connection name: a grant check hands this to the database, and a
         * connection name means nothing to a server. Null and never `''` — two empty role names
         * compare equal, so a check asking "may `''` alter this table" would certify a role that
         * does not exist.
         */
        public ?string $migrationRole = null,
        /**
         * How long a session must have been running before a check treats it as a collision risk.
         *
         * Carried here rather than read in the check, for the same reason the budget is: a check
         * that reached for the container would be a check that cannot be constructed without one,
         * and the deploy checks are deliberately plain objects over a context.
         *
         * The default matches the shipped configuration, so a context built by hand in a test
         * behaves like a real run instead of like a run with no threshold at all.
         */
        public int $longRunningMs = self::DEFAULT_LONG_RUNNING_MS,
        /** The replica lag at which a check reports, in milliseconds. */
        public int $replicationLagMs = self::DEFAULT_REPLICATION_LAG_MS,
    ) {}

    /**
     * How much of the run's budget is left, in milliseconds.
     *
     * Never negative: a check asking after the deadline has passed is told zero rather than a
     * negative number it would have to remember to clamp. Zero means "do not start something new",
     * which is a sentence every caller already knows how to read.
     */
    public function remainingBudgetMs(): int
    {
        $remaining = (int) round(($this->deadlineAt - hrtime(true)) / 1_000_000);

        return max(0, $remaining);
    }

    /** Whether the run has spent its budget. */
    public function isExhausted(): bool
    {
        return $this->remainingBudgetMs() === 0;
    }
}
