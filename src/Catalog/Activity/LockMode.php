<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Activity;

/**
 * What a held lock BLOCKS, said in a way both engines can answer.
 *
 * The cases are not translations of PostgreSQL's eight lock modes or of MySQL's metadata-lock
 * names. They are the distinctions a deploy gate acts on, and there are exactly this many because
 * finer ones do not change what anybody does: the question is always "will the migration I am about
 * to run have to wait behind this, and will it block the application while it waits".
 *
 * A rule or a preflight never sees a driver's own spelling. That is not tidiness — it is the same
 * reason the statistics sources name a quantity rather than a column: an engine-specific string in
 * the core is coupling that enters through data, and the core/driver split pays for it just as
 * dearly as it would for an import.
 *
 * **What is missing here is deliberate: there is no `Unknown` case.** A mode this build cannot name
 * is not a kind of lock; it is a gap in this package's knowledge, and giving it an enum case would
 * let it travel as if it had been understood. It travels as `null` beside the server's own string
 * instead — see {@see LockWait} — and the snapshot goes partial because of it.
 */
enum LockMode: string
{
    /**
     * Readers and writers both proceed; only a schema change is blocked.
     *
     * The lock an ordinary `SELECT` holds. Its presence in a preflight is almost never the answer
     * on its own — but it is the answer when the migration wants an exclusive lock, because then
     * even this one is in the way.
     */
    case Shared = 'shared';

    /**
     * Writers proceed alongside each other; a schema change waits.
     *
     * What an `INSERT`, `UPDATE` or `DELETE` holds on the table it touches. The most common thing a
     * migration actually queues behind on a busy system.
     */
    case SharedWrite = 'shared_write';

    /**
     * Reads proceed, writes wait.
     *
     * Held by operations that need a stable table while they run. An application meeting one keeps
     * serving pages and fails on saves, which is why it is worth telling apart from the case above:
     * the two produce very different incident reports.
     */
    case SharedNoWrite = 'shared_no_write';

    /**
     * Ordinary work proceeds; concurrent MAINTENANCE waits.
     *
     * The mode PostgreSQL's `SHARE UPDATE EXCLUSIVE` occupies, and the one most easily mistaken for
     * harmless. It does not block the application at all — but it does block `VACUUM`, `ANALYZE`,
     * and another `CREATE INDEX CONCURRENTLY`, so a migration built to be online can still queue
     * behind it indefinitely while every dashboard says the database is fine.
     */
    case MaintenanceExclusive = 'maintenance_exclusive';

    /**
     * Everything waits, including reads.
     *
     * The one that takes an application down. A migration needing it, or queued behind one, is the
     * finding a live preflight exists to produce.
     */
    case Exclusive = 'exclusive';

    /**
     * Whether a lock in this mode stops the application from reading.
     *
     * The question worth asking first, because it is the one whose answer is an outage.
     */
    public function blocksReads(): bool
    {
        return $this === self::Exclusive;
    }

    /** Whether a lock in this mode stops the application from writing. */
    public function blocksWrites(): bool
    {
        return $this === self::Exclusive || $this === self::SharedNoWrite;
    }

    /**
     * Whether a lock in this mode is compatible with an ONLINE index build.
     *
     * The distinction a migration written to be online turns on, and the one place where the modes
     * genuinely disagree: PostgreSQL's `CREATE INDEX CONCURRENTLY` takes a maintenance lock, so it
     * proceeds alongside ordinary readers and writers and waits only behind another maintenance
     * operation or an exclusive lock. A preflight that reported every held lock as "in the way"
     * would tell a project its online migration must wait when it need not, and the advice nobody
     * follows twice is the advice that was wrong once.
     *
     * This is deliberately NOT a `blocksSchemaChange()` predicate. That one was written first and
     * answered `true` for every case — which is both a method that cannot fail and, worse, untrue:
     * an ordinary `SELECT`'s lock does not block a concurrent index build at all.
     */
    public function allowsOnlineIndexBuild(): bool
    {
        return $this === self::Shared || $this === self::SharedWrite;
    }
}
