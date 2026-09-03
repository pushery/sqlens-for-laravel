<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * An account holds `PROCESS` — it can read every other session's current statement.
 *
 * The disclosure is not the session list; it is the STATEMENT TEXT in it. Anything a value was
 * interpolated into rather than bound travels in that text: a password being set, a token being
 * looked up, a customer record being written. `SHOW PROCESSLIST` and
 * `information_schema.PROCESSLIST` show it to anybody holding this privilege, including for
 * connections belonging to entirely different applications on the same server.
 *
 * ## Why `medium` rather than `high`
 *
 * It reads, and only what is in flight. It changes nothing, persists nothing, and reaches nothing
 * outside the server — which is the line between it and `FILE`. A finding that treated the two the
 * same would tell a reader nothing about which to fix first.
 *
 * ## The exclusion that matters most here
 *
 * A monitoring account NEEDS `PROCESS`, and so does the read-only audit account this package's own
 * documentation asks you to create. The connecting account is therefore never reported — the gate
 * lives in the shared base class, because a tool that flags the setup it recommends is a tool
 * nobody trusts twice.
 */
final class ProcessGrantRule extends AbstractServerReachRule
{
    public function id(): string
    {
        return 'SEC.PRIV.GRANT_PROCESS';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    protected function privilege(): string
    {
        return 'PROCESS';
    }

    protected function message(SchemaObject $object): string
    {
        return sprintf(
            '%s holds PROCESS, so it can see the CURRENT STATEMENT of every other session on this '
            .'server — including sessions belonging to other applications. The disclosure is the '
            .'statement TEXT rather than the session list: any value interpolated into SQL instead '
            .'of bound travels in it, so a password being set or a token being looked up is visible '
            .'to this account while it runs. It reads only what is in flight and changes nothing, '
            .'which is why this is not reported at the level FILE is. A monitoring or audit account '
            .'needs PROCESS and is expected to hold it — the account SQLens connects as is never '
            .'reported here. For an application account, REVOKE PROCESS ON *.* FROM %s.',
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
            'what PROCESS exposes depends on what other sessions actually run. On a server whose statements are fully parameterized it still shows the parameters, which is the part people are surprised by',
        ];
    }
}
