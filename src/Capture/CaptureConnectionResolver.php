<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Illuminate\Contracts\Config\Repository;
use Pushery\SQLens\Contracts\Driver;
use Pushery\SQLens\Drivers\DriverManager;
use Pushery\SQLens\Drivers\DriverResolutionFailure;

/**
 * Decides WHICH connection a capture runs against, and refuses to guess.
 *
 * Precedence is fixed and explicit: an explicit `--database` beats the package's
 * own `sqlens.connection`, which beats the application's default. Anything else —
 * inferring a connection from the migration, or falling back to a driver name —
 * would let two runs of the same repository target different databases.
 *
 * The driver itself is NOT resolved here. `DriverManager` already owns that,
 * including the read/write split (a capture always addresses the WRITE side; a
 * replica has different grammar preconditions and is the wrong target for a
 * migration anyway) and the named failure for an unsupported engine. Re-deriving
 * either here would create a second answer to the same question.
 */
final readonly class CaptureConnectionResolver
{
    public function __construct(
        private DriverManager $drivers,
        private Repository $config,
    ) {}

    /**
     * The connection name a capture uses.
     *
     * `--database` wins because a user who names a connection on the command line
     * has said something more specific than any file can.
     */
    public function connectionName(?string $explicit = null): string
    {
        if ($explicit !== null && $explicit !== '') {
            return $explicit;
        }

        return $this->drivers->defaultConnectionName();
    }

    /**
     * The driver for the resolved connection, or a named failure.
     *
     * An unsupported engine (SQLite, MariaDB) comes back as a `DriverResolutionFailure`
     * and must be turned into an `undetermined` result by the caller — never a
     * `pass`, and never a partial run. Declared non-goals produce a clear message,
     * not half support.
     */
    public function resolve(?string $explicit = null): Driver|DriverResolutionFailure
    {
        return $this->drivers->resolve($this->connectionName($explicit));
    }

    /**
     * The session budgets this capture must apply before its first query, in
     * milliseconds.
     *
     * Read from config rather than hardcoded so an application can tighten them,
     * and validated by the config schema so they can never be zero or negative —
     * "wait forever" is the one value a guard against long waits must not accept.
     *
     * @return array{statement_timeout: int, lock_timeout: int}
     */
    public function sessionBudget(): array
    {
        return [
            'statement_timeout' => $this->positiveInt('sqlens.capture.session.statement_timeout'),
            'lock_timeout' => $this->positiveInt('sqlens.capture.session.lock_timeout'),
        ];
    }

    /**
     * A configured budget, or the shipped default when the host published a
     * config from an older version that predates the key. Falling back is right
     * here and wrong for a connection name: a missing budget has one safe answer,
     * a missing connection does not.
     */
    private function positiveInt(string $path): int
    {
        $value = $this->config->get($path);

        return is_int($value) && $value > 0 ? $value : self::DEFAULTS[$path];
    }

    /** The shipped defaults, mirrored from `config/sqlens.php`. */
    private const array DEFAULTS = [
        'sqlens.capture.session.statement_timeout' => 5000,
        'sqlens.capture.session.lock_timeout' => 3000,
    ];
}
