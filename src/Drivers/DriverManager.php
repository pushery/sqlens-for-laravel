<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers;

use Illuminate\Contracts\Config\Repository;
use Pushery\SQLens\Contracts\Driver;
use Pushery\SQLens\Contracts\Rule;

/**
 * Resolves a Laravel connection name to a supported Driver — always from the
 * config the FRAMEWORK would use, never a guess and never the raw array.
 * Reading config is all it needs; it opens no connection and touches no server.
 *
 * "The config the framework would use" is doing real work in that sentence. Laravel
 * never reads `database.connections.<name>` verbatim: it runs the entry through
 * ConfigurationUrlParser (so a `url`-only connection HAS a driver, extracted from
 * the scheme) and, for a read/write split, merges the `write` block over the base.
 * Reading the raw array instead would report "no driver key" for a perfectly valid
 * url-based connection, and would miss a driver overridden on the write side.
 *
 * Three-valued by construction: a missing connection, a connection with no driver
 * key, a reserved non-goal engine (mariadb/sqlite/sqlsrv), or an unknown driver
 * each yield a named DriverResolutionFailure — never a silent fallback to another
 * driver. A reserved driver is told apart from a genuinely unknown one by asking
 * the registry (the one place the reserved list lives).
 */
final readonly class DriverManager
{
    public function __construct(
        private DriverRegistry $registry,
        private Repository $config,
    ) {}

    /**
     * Every rule every registered driver serves, keyed by id.
     *
     * Offered here rather than by handing callers the registry: a caller that held the registry
     * could also resolve a concrete driver from it, and driver isolation is exactly what the
     * manager exists to keep. What a configuration check needs is the ID SET — across drivers,
     * because a baseline is written before a connection is resolved, and across suites, because
     * "names nothing" and "names something that does not run here" are different mistakes and only
     * the full set can tell them apart.
     *
     * @return array<string, Rule>
     */
    public function everyRule(): array
    {
        $rules = [];

        foreach ($this->registry->all() as $driver) {
            foreach ($driver->rules() as $rule) {
                $rules[$rule->id()] = $rule;
            }
        }

        return $rules;
    }

    /**
     * The finding-id prefix of every tool any driver ships — `SQUAWK.`, `PGLS.`, and whatever a
     * driver package adds next.
     *
     * ## Derived, never listed
     *
     * The derivation lives on the registry, because three callers need it and only two hold a
     * manager. This is the door for the ones that do — same reason {@see everyRule()} above exists
     * here rather than handing callers the registry.
     *
     * ## Why the manager offers it rather than the registry
     *
     * Same reason as `everyRule()`: a caller that held the registry could resolve a concrete driver
     * from it, and driver isolation is what this class exists to keep. A configuration check needs
     * the namespace SET, never a particular engine's.
     *
     * @return list<string> sorted by byte, so a message built from it reads the same everywhere
     */
    public function everyToolPrefix(): array
    {
        return $this->registry->everyToolPrefix();
    }

    /**
     * The connection name a suite resolves when none is given explicitly:
     * `sqlens.connection` if set, otherwise the host's default connection
     * (`database.default`). `null` for `sqlens.connection` means "the host
     * default" — never a guessed 'pgsql'.
     */
    public function defaultConnectionName(): string
    {
        $configured = $this->config->get('sqlens.connection');

        if (is_string($configured) && $configured !== '') {
            return $configured;
        }

        $default = $this->config->get('database.default');

        return is_string($default) ? $default : '';
    }

    /**
     * The configured connection NAMES, sorted so the message is deterministic.
     * Names only: a host, a user or a password must never reach a finding.
     *
     * @param  array<string, mixed>  $connections
     * @return list<string>
     */
    private function names(array $connections): array
    {
        $names = array_map(strval(...), array_keys($connections));
        sort($names, SORT_STRING);

        return $names;
    }

    /**
     * The connection config as the framework resolves it, from the WRITE side.
     *
     * The write side is a decision, not a detail: a replica can differ from the
     * primary, and every judgment SQLens makes is about the instance a migration
     * will actually run against. Laravel's own ConnectionFactory merges the `write`
     * block over the base for exactly this reason, so the same merge happens here.
     *
     * @return array<string, mixed>
     */
    private function writeSideConfig(mixed $config): array
    {
        return EffectiveConnectionConfig::for($config);
    }

    public function resolve(string $connectionName): Driver|DriverResolutionFailure
    {
        /** @var array<string, mixed> $connections */
        $connections = $this->config->get('database.connections', []);

        // Laravel's own test is `Arr::get($connections, $name) === null`, NOT
        // `has()`: a connection configured as null exists as a key but is
        // "not configured" to the framework. Matching it here keeps SQLens from
        // reporting a different cause than the framework would for the same config.
        if (($connections[$connectionName] ?? null) === null) {
            return DriverResolutionFailure::connectionNotFound($connectionName, $this->names($connections));
        }

        $driver = $this->writeSideConfig($connections[$connectionName])['driver'] ?? null;

        if (! is_string($driver) || $driver === '') {
            return DriverResolutionFailure::missingDriverKey($connectionName);
        }

        $resolved = $this->registry->resolve($driver);

        if ($resolved instanceof Driver) {
            return $resolved;
        }

        return $this->registry->isReserved($driver)
            ? DriverResolutionFailure::reservedDriver($driver)
            : DriverResolutionFailure::unknownDriver($driver);
    }
}
