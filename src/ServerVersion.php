<?php

declare(strict_types=1);

namespace Pushery\SQLens;

use Illuminate\Database\DatabaseManager;
use PDO;
use Pushery\SQLens\Drivers\DriverManager;

/**
 * The ONE place SQLens learns which server it is looking at.
 *
 * Every judgment that depends on the server — the per-driver version floor, the
 * "is this really MariaDB behind Laravel's mysql driver" question, the version
 * window a rule declares — reads the banner from here. A second acquisition site
 * would mean two judgments about the same server in one run, and the two would
 * eventually disagree.
 *
 * It never opens a connection. `getRawPdo()` hands back the PDO the connection is
 * ALREADY holding and resolves nothing; `getPdo()` would call the lazy connection
 * closure, which is a connect — and connecting to a production database to find
 * out its version is exactly the harm this package promises not to do. It also
 * runs no query at all: the banner is an attribute of an existing handle.
 *
 * Note the deliberate namespace. `Pushery\SQLens\Rules\ServerVersion` is a
 * different thing entirely — it parses a version STRING into numbers and compares
 * them, and its namespace is forbidden from importing PDO or Illuminate at all.
 * This class acquires the raw string; that one reasons about it.
 */
final readonly class ServerVersion
{
    public function __construct(
        private DatabaseManager $database,
        private DriverManager $drivers,
    ) {}

    /**
     * The server's own version banner for a connection, or null when it cannot be
     * had. Null is never a guess — it is one of three named causes the caller maps
     * to UndeterminedReason::UnknownServerVersion:
     *
     *   1. nothing is connected yet (the `--file` fast path never opens a database)
     *   2. the driver reports no server version attribute
     *   3. the reported banner is empty
     *
     * The RAW string is returned on purpose: the `assume_server_version` pin and
     * the parsing both belong to their own units, so this one stays a single,
     * testable act of acquisition.
     */
    public function resolve(?string $connection = null): ?string
    {
        $name = $connection ?? $this->drivers->defaultConnectionName();

        // Reading the WRITE side is a decision, not an accident: a read replica can
        // lag a major version behind, and every judgment SQLens makes is about the
        // instance a migration will actually run against.
        $pdo = $this->database->connection($name)->getRawPdo();

        if (! $pdo instanceof PDO) {
            return null;
        }

        $banner = $pdo->getAttribute(PDO::ATTR_SERVER_VERSION);

        if (! is_string($banner) || $banner === '') {
            return null;
        }

        return $banner;
    }
}
