<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

use DateTimeImmutable;
use Pushery\SQLens\Contracts\ShadowDatabaseCatalog;
use Throwable;

/**
 * Finds and removes shadow databases a previous run leaked — the safety net for the
 * one teardown path a `try/finally` cannot cover: a process killed mid-run (SIGKILL,
 * a fatal, a power loss) never reaches its own cleanup, so the leaked database is
 * removed on a LATER run instead.
 *
 * Two guarantees keep this from ever touching a database the tool did not create:
 *
 *   - It lists ONLY databases carrying the shadow prefix (the catalog filters), so a
 *     user's own database can never enter the candidate set.
 *   - It ages a candidate by the timestamp embedded in its NAME, not by any server
 *     metadata; a name that does not match the scheme is never aged and so never
 *     dropped. Only databases OLDER than the configured threshold are swept, so a
 *     shadow database from a run happening right now is never removed out from under
 *     it.
 *
 * Dropping is a database-mutating action, so it happens ONLY behind the production
 * guard: a blocked decision still REPORTS the orphans (a leak the user should see)
 * but removes nothing. "No silent green" applies to cleanup too — a found-but-kept
 * orphan is visible in the report, never a quiet no-op.
 *
 * The same rule covers a drop that FAILS. The name stays in `orphansFound` and never
 * reaches `dropped`, so the difference between the two arrays is the set that could
 * not be removed — and one obstinate database does not stop the sweep of the rest,
 * because the commonest cause is a connection that will be gone by the next run.
 */
final readonly class ShadowOrphanSweeper
{
    public function __construct(
        private ShadowDatabaseCatalog $catalog,
        private string $prefix,
        private int $thresholdSeconds,
    ) {}

    /**
     * List the stale shadow databases and, if the guard allows, drop them. $now is
     * injected so the age boundary is deterministic and testable.
     */
    public function sweep(GuardDecision $decision, DateTimeImmutable $now): ShadowSweepReport
    {
        $cutoff = $now->getTimestamp() - $this->thresholdSeconds;

        $orphans = [];

        foreach ($this->catalog->listDatabasesWithPrefix($this->prefix) as $name) {
            $timestamp = ShadowDatabaseName::timestampOf($name, $this->prefix);

            // A name we cannot age (not our format) is left alone; only a database
            // whose embedded time is at or before the cutoff is a stale orphan.
            if ($timestamp instanceof DateTimeImmutable && $timestamp->getTimestamp() <= $cutoff) {
                $orphans[] = $name;
            }
        }

        $dropped = [];

        if (! $decision->isBlocked()) {
            foreach ($orphans as $name) {
                try {
                    $this->catalog->dropDatabase($name);
                    $dropped[] = $name;
                } catch (Throwable) {
                    // One orphan that refuses to go must not stop the others. A leaked database
                    // still holding a connection is the commonest case, and it is exactly the one
                    // where the NEXT sweep succeeds — so aborting here would turn a transient
                    // obstacle into a permanent leak of everything behind it in the list.
                    //
                    // Nothing is swallowed: the name stays in `orphansFound` and is absent from
                    // `dropped`, so the difference between the two arrays IS the set that could not
                    // be removed. A caller that reports one and not the other would be inventing
                    // the silence, not inheriting it.
                }
            }
        }

        return new ShadowSweepReport($orphans, $dropped);
    }
}
