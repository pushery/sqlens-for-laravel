<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * An account holds `FILE` — the bridge from a SQL injection to the file system.
 *
 * This is the privilege that turns a database problem into a machine problem. `LOAD_FILE()` reads any
 * file the MySQL server process can read, and `SELECT … INTO OUTFILE` writes one — as the server's
 * operating-system user, not as the person connecting. An injection reaching an account with `FILE`
 * does not have to escalate anywhere: it can read configuration, keys and other applications' data
 * off the same host, and write a file somewhere the host will later execute.
 *
 * ## The honest limit, which is `secure_file_priv`
 *
 * How far it actually reaches depends on a server setting the grant knows nothing about.
 * `secure_file_priv` set to a directory confines both operations to it; set to the empty string, it
 * confines nothing; set to NULL, it disables them entirely. So the finding states the privilege and
 * points at the setting rather than claiming a reach it has not measured — the two are separate
 * facts, and reporting the second one here would be a second alarm for a finding that belongs to the
 * server-settings suite.
 */
final class FileGrantRule extends AbstractServerReachRule
{
    public function id(): string
    {
        return 'SEC.PRIV.GRANT_FILE';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    protected function privilege(): string
    {
        return 'FILE';
    }

    protected function message(SchemaObject $object): string
    {
        return sprintf(
            '%s holds FILE, which lets it read and write files AS THE SERVER PROCESS: LOAD_FILE() '
            .'reads anything the mysqld user can read, and SELECT … INTO OUTFILE writes it back. A '
            .'SQL injection reaching this account therefore does not stay inside the database — it '
            .'reads configuration, keys and other applications data off the same host, and can drop '
            .'a file where the host will later run it. How far that reaches depends on the server '
            .'setting secure_file_priv, which this finding does not measure: check it separately, '
            .'because a directory confines both operations to it and NULL disables them entirely. '
            .'An application account has no use for FILE — REVOKE FILE ON *.* FROM %s.',
            $this->grantee($object),
            $this->grantee($object),
        );
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'reads the catalog, not the connections: a privilege held by an account nothing ever authenticates as is the same rows as one in daily use',
            'the exposure depends on what else can reach this account. FILE turns a SQL injection into filesystem access, so its weight is decided by the application in front of the database — which this package does not read',
        ];
    }
}
