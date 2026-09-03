<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical\Extensions;

use Closure;
use Pushery\SQLens\Contracts\DriverCanonicalization;
use Pushery\SQLens\Drivers\DriverManager;
use Pushery\SQLens\Drivers\DriverResolutionFailure;
use Pushery\SQLens\Drivers\Mysql\Canonical\MysqlCanonicalization;
use Pushery\SQLens\Drivers\Pgsql\Canonical\PgsqlCanonicalization;
use Pushery\SQLens\Exceptions\InvalidDriverRegistration;

/**
 * The one sanctioned bridge between the canonicalization layer and the drivers:
 * it resolves a connection to its driver through the manager (config → driver
 * key, no match-cascade in the core) and hands back that driver's
 * canonicalization. A third-party driver plugs its canonicalization in through
 * extend(), so a new driver is added without touching a core file.
 *
 * Three-valued by construction: an unknown or reserved driver, a missing
 * connection or driver key (all propagated from the manager), a driver with no
 * registered canonicalization, or a canonicalization that leaves a required
 * capability empty each yield a named ExtensionFailure — never an exception,
 * never a silent fallback to another driver.
 */
final class CanonicalExtensionRegistry
{
    /** @var array<string, Closure(): DriverCanonicalization> */
    private array $creators = [];

    public function __construct(private readonly DriverManager $manager)
    {
        $this->register('pgsql', static fn (): DriverCanonicalization => new PgsqlCanonicalization);
        $this->register('mysql', static fn (): DriverCanonicalization => new MysqlCanonicalization);
    }

    /**
     * Register a NEW driver's canonicalization. A duplicate key throws rather than
     * silently overwriting.
     *
     * @param  Closure(): DriverCanonicalization  $creator
     */
    public function extend(string $driverKey, Closure $creator): void
    {
        $this->register($driverKey, $creator);
    }

    /**
     * The canonicalization for a connection, or a named failure. Resolution goes
     * through the driver manager (config view), so it opens no connection.
     */
    public function forConnection(string $connectionName): DriverCanonicalization|ExtensionFailure
    {
        $driver = $this->manager->resolve($connectionName);

        if ($driver instanceof DriverResolutionFailure) {
            return ExtensionFailure::fromResolution($driver);
        }

        return $this->forDriver($driver->key());
    }

    /**
     * The same answer for a caller that has already resolved the driver.
     *
     * `DriverCaptorFactory` is the one: it resolves the driver first because it needs the key for
     * several other pieces, and asking this registry by connection would resolve it a second time.
     *
     * It exists so that path can go THROUGH this registry rather than beside it. It used to map
     * `pgsql`/`mysql` to the same two canonicalizations in its own `match`, which is how a registry
     * that calls itself the one sanctioned bridge ended up with no caller — and how `extend()`
     * became a method that accepted registrations nobody would ever read.
     */
    public function forDriver(string $key): DriverCanonicalization|ExtensionFailure
    {
        $creator = $this->creators[$key] ?? null;

        if ($creator === null) {
            return ExtensionFailure::missingCanonicalization($key);
        }

        $canonicalization = $creator();
        $missingCapability = $this->missingCapability($canonicalization);

        if ($missingCapability !== null) {
            return ExtensionFailure::incompleteCapability($key, $missingCapability);
        }

        return $canonicalization;
    }

    /**
     * @param  Closure(): DriverCanonicalization  $creator
     */
    private function register(string $driverKey, Closure $creator): void
    {
        if (isset($this->creators[$driverKey])) {
            throw InvalidDriverRegistration::duplicateKey($driverKey);
        }

        $this->creators[$driverKey] = $creator;
    }

    /** The first required capability the canonicalization leaves empty, or null if complete. */
    private function missingCapability(DriverCanonicalization $canonicalization): ?string
    {
        if ($canonicalization->quotingCharacter() === '') {
            return 'quoting character';
        }

        if ($canonicalization->keywords() === []) {
            return 'keyword list';
        }

        if ($canonicalization->stringLiteralDelimiters() === []) {
            return 'string literal delimiter';
        }

        return null;
    }
}
