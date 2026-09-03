<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Catalog\SettingCrossFacts;

/**
 * Measures what a server-baseline rule needs BESIDE the setting it judges.
 *
 * A setting on its own is an abstraction: "this flag is dangerous". The same finding carrying the
 * fourteen columns it already affects is something a reader can act on this afternoon. That second
 * half is a catalog question, not a settings question, which is why it has its own collector rather
 * than growing {@see ServerSettingsReader}.
 *
 * ## The obligation the implementations carry
 *
 * Never guess the state from the value. An empty result with `Measured` and an empty result with
 * `Unavailable` are the same bytes and opposite claims, and only the collector — which knows whether
 * its query ran — can tell them apart. Returning "none" because a query threw is the defect this
 * whole arrangement exists to make impossible.
 */
interface SettingCrossFactCollector
{
    /**
     * Where the general query log is being written, as the server's own `log_output` string.
     *
     * The name lives on the CONTRACT rather than on the engine's collector, and that placement is
     * the topology rule rather than a preference: the rule that consumes this fact is
     * driver-neutral, so naming the MySQL collector from it would be a core file reaching into a
     * driver-bound one — an unresolvable class the day the packages split.
     *
     * The other fact names on that collector stay where they are, because only driver-tree rules
     * read them. This is the first one a neutral rule needs.
     */
    public const string GENERAL_LOG_OUTPUT = 'general_log_output';

    /** Everything this driver can measure alongside its settings, keyed by variable. */
    public function collect(): SettingCrossFacts;
}
