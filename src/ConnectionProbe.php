<?php

declare(strict_types=1);

namespace Pushery\SQLens;

use Illuminate\Database\DatabaseManager;
use PDO;

/**
 * The one place in this package that OPENS a connection on purpose.
 *
 * {@see ServerVersion} deliberately does not, and that is not an oversight to be corrected: reading
 * `getRawPdo()` hands back the handle a connection is ALREADY holding, so a lint run never touches
 * a database it was not told to touch. Every rule path depends on that, and it stays.
 *
 * But the same restraint made `sqlens:doctor` unable to answer its own question. Measured in a
 * fresh CLI child with correct credentials and a reachable PostgreSQL 18: every configured
 * connection reported `undetermined`, INCLUDING `sqlite` — which needs no server, no credentials
 * and no network. Nothing had connected yet, so there was no handle to read, so there was no
 * version. A healthy environment and a broken one printed the same line, and the whole purpose of
 * a diagnostic is to tell those two apart.
 *
 * So the connect lives here, behind `sqlens:doctor --probe`, and never on a default path:
 *
 *  - it happens only when a human asked a diagnostic command to go and look;
 *  - it is a handshake and an attribute read — no query, no write, no lock;
 *  - and it is a separate class rather than a second mode of ServerVersion, so "this unit never
 *    connects" stays a property somebody can check by reading one file.
 */
final readonly class ConnectionProbe
{
    public function __construct(private DatabaseManager $database) {}

    /**
     * Open the named connection and read the server's own version banner.
     *
     * `getPdo()` rather than `getRawPdo()`: resolving the lazy closure IS the connect, and here
     * that is the point rather than the hazard. Null means the handshake succeeded and the driver
     * reported no version attribute — a third state, distinct from both a version and a failure,
     * and the caller must keep it distinct.
     *
     * Throws whatever the driver throws. Callers report the failure TYPE and never its message: a
     * PDO connect error routinely spells out host, port and username, and this output is pasted
     * into issues.
     */
    public function banner(string $connection): ?string
    {
        $banner = $this->database->connection($connection)->getPdo()->getAttribute(PDO::ATTR_SERVER_VERSION);

        return is_string($banner) && $banner !== '' ? $banner : null;
    }
}
