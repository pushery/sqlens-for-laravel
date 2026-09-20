<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Settings;

/**
 * What it takes to change a server variable — and, for one of these, that it cannot be changed.
 *
 * Load-bearing rather than descriptive. A finding that says "set this to X" is advice; the same
 * finding about an `initdb` variable is advice nobody can follow, and a reader who tries will spend
 * an afternoon discovering that. So a rule consults this before it words its remediation.
 */
enum SettingChangeCost: string
{
    /** Any session may set it — including ours, which is why the server's own value has to be read separately. */
    case Session = 'session';

    /** A configuration reload picks it up; no downtime. */
    case Reload = 'reload';

    /** It takes effect on restart — real downtime to plan, not a config edit. */
    case Restart = 'restart';

    /**
     * Changeable in place, but only while the server is stopped — a maintenance window, not a migration.
     *
     * ⚠️ **This case was missing, and its absence cost the most expensive kind of wrong advice.**
     * `changeable` knew only session, reload, restart and initdb, so `data_checksums` fell into the
     * most expensive bucket and the finding told a reader that *moving it means a new cluster and a
     * dump/restore*. Since PostgreSQL 12 it does not: `pg_checksums --enable` turns them on in the
     * existing data directory.
     *
     * Verified rather than read off the manual — `pg_checksums --help` on 18.0 lists `-e, --enable`,
     * and run against a running cluster it answers `pg_checksums: error: cluster must be shut down`,
     * which is the shutdown requirement stated by the tool itself.
     *
     * The two plans differ by orders of magnitude, and the sentence sits in the finding — exactly
     * where somebody is deciding which of them to schedule.
     */
    case Offline = 'offline';

    /**
     * Fixed when the cluster was initialized. It cannot be changed at all.
     *
     * `lower_case_table_names` is the one that matters here: MySQL fixes it at initialization and
     * changing it afterwards is unsupported. A rule about it reports a fact to plan a migration
     * around, never a setting to correct.
     *
     * ⚠️ `data_checksums` used to be named here too and has moved to {@see self::Offline}.
     */
    case Initdb = 'initdb';

    /**
     * Whether a finding about this variable may propose changing it at all.
     *
     * `Offline` is fixable. What it costs is downtime, which the sentence beside the finding states —
     * and calling it unfixable would suppress a proposal somebody can actually carry out.
     */
    public function isFixable(): bool
    {
        return $this !== self::Initdb;
    }
}
