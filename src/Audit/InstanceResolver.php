<?php

declare(strict_types=1);

namespace Pushery\SQLens\Audit;

use Illuminate\Contracts\Config\Repository;
use Pushery\SQLens\Contracts\Driver;
use Pushery\SQLens\Contracts\InstanceIdentityReader;
use Pushery\SQLens\Drivers\DriverRegistry;
use Pushery\SQLens\Drivers\DriverResolutionFailure;
use Pushery\SQLens\Drivers\EffectiveConnectionConfig;

/**
 * Decides which instance an audit addresses — from configuration alone, never from a connection.
 *
 * SQL-free by construction: it reads config, applies four rules in order, and hands back a target
 * or a named refusal. What the server actually is gets asked later, through
 * {@see InstanceIdentityReader}, by whoever holds a session. That split
 * is what keeps the core free of engine vocabulary — and it is also honest about sequence, since
 * the instance has to be CHOSEN before anything can connect to it.
 *
 * ## The four rules, and the one that is a refusal
 *
 * 1. `--connection` was given → it holds. The operator said which.
 * 2. `sqlens.connection` is configured → it holds. The project said which, once, in writing. That is
 *    the SAME key the capture and lint paths read, deliberately: a project that stated its
 *    connection once should not find the audit reading a different one, and the audit-scoped key
 *    this originally named was never in the shipped config file — so the rule was reachable from a
 *    test and from nowhere else.
 * 3. Exactly ONE supported connection exists → it holds, and the report names it. There was nothing
 *    to choose between.
 * 4. Otherwise → refused, listing the candidates.
 *
 * Rule 4 is the point of the whole class. Laravel's `database.default` is deliberately not consulted
 * as a fallback: it is the right default for an application's own queries and the wrong one for an
 * audit, because which instance was read is part of what the report asserts. A primary and its
 * replica disagree about settings, about lag, sometimes about schema — so a silently chosen one puts
 * a claim in the report that nobody made, and the reader has no way to notice.
 */
final readonly class InstanceResolver
{
    public function __construct(private Repository $config, private DriverRegistry $drivers) {}

    /**
     * @param  string|null  $requested  the `--connection` flag, or null when it was not given
     * @param  string|null  $pinnedHost  the `--host` flag, or null when it was not given
     */
    public function resolve(?string $requested = null, ?string $pinnedHost = null): InstanceResolution
    {
        $name = $requested ?? $this->configuredName();

        if ($name === null) {
            $supported = $this->supportedConnections();

            return count($supported) === 1
                ? $this->target($supported[0], $pinnedHost ?? $this->configuredHost())
                : InstanceResolution::ambiguous($supported);
        }

        return $this->target($name, $pinnedHost ?? $this->configuredHost());
    }

    /** The host this project pinned for audits, or null when it pinned none. */
    private function configuredHost(): ?string
    {
        $host = $this->config->get('sqlens.host');

        return is_string($host) && $host !== '' ? $host : null;
    }

    /** The connection this project pinned, or null when it pinned none. */
    private function configuredName(): ?string
    {
        $name = $this->config->get('sqlens.connection');

        return is_string($name) && $name !== '' ? $name : null;
    }

    /**
     * Every configured connection this package can reason about, sorted.
     *
     * Sorted so the refusal message lists candidates in the same order on every machine — an
     * operator comparing two runs' output should not have to notice that only the order changed.
     *
     * @return list<string>
     */
    private function supportedConnections(): array
    {
        $connections = $this->config->get('database.connections');

        if (! is_array($connections)) {
            return [];
        }

        $supported = [];

        foreach ($connections as $name => $settings) {
            // Through the parser, like everywhere else: a `url`-only connection carries no
            // `driver` key, so reading the key straight out dropped it from the supported list and
            // the audit then reported an ambiguity — or no candidate at all — over a configuration
            // Laravel resolves perfectly well.
            $driver = EffectiveConnectionConfig::driverFor($settings);

            if (is_string($name) && is_string($driver) && $this->drivers->resolve($driver) instanceof Driver) {
                $supported[] = $name;
            }
        }

        sort($supported);

        return $supported;
    }

    /** A named connection turned into a target, or the reason it cannot be one. */
    private function target(string $name, ?string $pinnedHost = null): InstanceResolution
    {
        $settings = $this->config->get("database.connections.{$name}");

        if (! is_array($settings)) {
            return InstanceResolution::unsupported(DriverResolutionFailure::connectionNotFound(
                $name,
                $this->configuredConnectionNames(),
            ));
        }

        // Only the DRIVER comes through the parser. `$settings` deliberately stays raw, because
        // ReadTopology reads the `read` block out of it below — and the parser's write-side merge
        // strips `read` and `write` by design. Replacing the array here made every read/write-split
        // topology invisible, which eight tests said out loud.
        $driver = EffectiveConnectionConfig::driverFor($settings);

        if ($driver === null) {
            return InstanceResolution::unsupported(DriverResolutionFailure::missingDriverKey($name));
        }

        if ($this->drivers->isReserved($driver)) {
            // A reserved engine is refused by name rather than half-supported. MariaDB answers the
            // same Laravel driver as MySQL and does not share its semantics, so reasoning about it
            // would mean reporting MySQL's rules on a server that does not follow them.
            return InstanceResolution::unsupported(DriverResolutionFailure::reservedDriver($driver));
        }

        if (! $this->drivers->resolve($driver) instanceof Driver) {
            return InstanceResolution::unsupported(DriverResolutionFailure::unknownDriver($driver));
        }

        $topology = ReadTopology::of($settings);

        // Refused BEFORE anything connects, because the choice is the problem. Laravel shuffles a
        // host array and picks the read and write sides independently, so leaving it to the
        // framework means two runs of an unchanged project can reach different servers — and the
        // difference between a primary and its replica reads as drift in a report that never said
        // which one answered.
        if ($pinnedHost === null && $topology->isAmbiguous()) {
            return InstanceResolution::ambiguousReadHosts($topology->hosts);
        }

        // A pin the configuration does not offer is a typo, and obeying it would audit a server the
        // project never configured — worse than not running at all.
        //
        // A connection that offers NO host is refused too, and that used to be the hole here: the
        // check was skipped whenever the list was empty, which is exactly the case of a socket, a
        // DSN or a `url` connection. `--host` was then taken at face value and dialled — the
        // project's credentials sent over TCP to a machine the operator named and the configuration
        // had never heard of, while the flag's own help text and the shipped docs both say such a
        // host is refused and never dialled. Offering nothing is not offering everything.
        if ($pinnedHost !== null && ! $topology->offers($pinnedHost)) {
            return InstanceResolution::unofferedHost($pinnedHost, $topology->hosts);
        }

        $host = $settings['host'] ?? null;
        $port = $settings['port'] ?? null;
        $database = $settings['database'] ?? null;

        // The host this run is actually pinned to: the operator's, or the single one the
        // configuration leaves. Null when there was nothing to choose — not a default.
        $pinned = $pinnedHost ?? $topology->onlyHost();

        return InstanceResolution::resolved(InstanceTarget::of(
            connection: $name,
            driver: $driver,
            // A `host` that is an ARRAY is recorded as no configured host at all, and that is the
            // honest reading: Laravel shuffles such a list, so the configuration states a SET of
            // possibilities rather than an expectation. What the run is pinned to travels separately.
            configuredHost: is_string($host) && $host !== '' ? $host : null,
            configuredPort: is_numeric($port) ? (int) $port : null,
            configuredDatabase: is_string($database) && $database !== '' ? $database : null,
            pinnedHost: $topology->configuresSplit || $topology->isAmbiguous() || $pinnedHost !== null ? $pinned : null,
        ));
    }

    /** @return list<string> */
    private function configuredConnectionNames(): array
    {
        $connections = $this->config->get('database.connections');

        if (! is_array($connections)) {
            return [];
        }

        $names = array_values(array_filter(array_keys($connections), is_string(...)));
        sort($names);

        return $names;
    }
}
