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
     * Fixed when the cluster was initialized. It cannot be changed at all.
     *
     * `data_checksums` and `lower_case_table_names` are the two that matter here. A rule about one
     * of them reports a fact to plan a migration around — a new cluster and a dump/restore — never
     * a setting to correct.
     */
    case Initdb = 'initdb';

    /** Whether a finding about this variable may propose changing it at all. */
    public function isFixable(): bool
    {
        return $this !== self::Initdb;
    }
}
