<?php

declare(strict_types=1);

namespace Pushery\SQLens\Audit;

/**
 * Whether the server this run examines OUTLIVES the run — and therefore whether its own
 * configuration is a deployment or a fixture.
 *
 * ## Why this changes the meaning of a finding rather than hiding one
 *
 * The sibling of {@see InstanceRole}, and for the same reason: some findings say two different
 * things depending on where they were read. `pg_hba.conf` accepting `trust`, `ssl = off` and a
 * connection role that is a superuser are three of the most serious things this package can report
 * about a server somebody deploys onto. About a container the pipeline creates at the start of a
 * job and destroys at the end, they are three descriptions of a test fixture — nobody outside the
 * job can reach it, nothing in it survives, and the settings were chosen by whoever wrote the
 * service block, not by whoever will operate the database.
 *
 * Measured before this existed: a consumer's `sqlens:audit --profile=ci` ended with exit 3 on a
 * freshly migrated schema, blocked by four `SEC.AUTH.HBA_TRUST`, one `SEC.PRIV.ROLE_SUPERUSER` and
 * one `SEC.CFG.TLS_DISABLED` — none of which said anything about the application. The pipeline's
 * answer was a shell script that filtered those rule families out of SQLens' own `blocked_by` list,
 * which means a lane had started deciding which of the package's blocks count. That decision is the
 * package's to make, and this is the package making it.
 *
 * ## Declared, never probed — and the default is the pessimistic one
 *
 * There is no cheap fact that distinguishes a throwaway container from a production server. Both
 * answer every query identically; the difference is what somebody INTENDS, and intent is not
 * readable from a catalog. So unlike {@see InstanceRole}, this has no undetermined case and no
 * detection: a project declares it, or it is {@see Persistent}.
 *
 * Silence therefore keeps every server check reporting, which is the only safe direction. Reading
 * silence as "probably a container" would turn the strictest checks in the package off for every
 * project that never heard of the key — and a security check that stops reporting without anybody
 * asking is the exact failure this package exists to refuse.
 *
 * ## What it does NOT touch, and this is the load-bearing half
 *
 * Only the checks whose subject IS the server or the role the audit connects as. Everything about
 * the SCHEMA — the thing the pipeline is actually there to judge, and the thing that will be
 * deployed onto a real server — reports unchanged. A declaration that quieted schema findings would
 * be a way to make a red run green, which is a different feature and one this package should not
 * have.
 *
 * The checks it quiets are not lost either. They are exactly the checks `sqlens:predeploy` runs
 * against the target host, where the same server facts are real and a finding about them is
 * actionable — so the declaration moves a question rather than dropping it, and the report says so.
 */
enum ServerLifetime: string
{
    /**
     * The server outlives the run: somebody deploys onto it, operates it, and connects to it from
     * outside whatever produced this report. Its configuration is a deployment and is judged as one.
     */
    case Persistent = 'persistent';

    /**
     * The server is created and destroyed by the job that audits it. Its authentication file, its
     * transport security and the attributes of its connection role describe a fixture.
     */
    case Disposable = 'disposable';

    /**
     * The declared lifetime, with anything unrecognized reading as {@see Persistent}.
     *
     * A typo must not be the quiet way to turn the server checks off, and the validator is what
     * reports it as a misconfiguration — this is only the direction the reading falls in while that
     * report is being made.
     */
    public static function declared(?string $value): self
    {
        return self::tryFrom((string) $value) ?? self::Persistent;
    }

    /** Whether findings about the server itself describe a fixture rather than a deployment. */
    public function isDisposable(): bool
    {
        return $this === self::Disposable;
    }
}
