<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Severity\Severity;

/**
 * An ordinary account that may connect from any host.
 *
 * `medium`, deliberately. `%` is a real widening — the account is reachable from every address the
 * server is — but on an account with ordinary privileges it is a pattern to tighten rather than an
 * incident. Reporting it louder would put a permanent line in the report of every deployment that
 * has a good reason for it, and the accounts with the best reasons belong to the people with the
 * most accounts.
 */
final class WildcardHostRule extends AbstractWildcardHostRule
{
    public function id(): string
    {
        return 'SEC.AUTH.ROLE_WILDCARD_HOST';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    protected function judgesPrivilegedAccounts(): bool
    {
        return false;
    }

    protected function message(string $account): string
    {
        return sprintf(
            '%s may connect from ANY host: the host half of a MySQL account name is an access control, and '
            .'`%%` matches every address the server can be reached at. This account holds ordinary '
            .'privileges, so this is a pattern worth tightening rather than an emergency — narrow it to the '
            .'network the client actually comes from, e.g. RENAME USER %s TO \'…\'@\'10.0.0.%%\'. '
            .'A wildcard host is a deliberate and correct choice for some accounts — replication and '
            .'monitoring reach the server from addresses nobody wants to enumerate — and this finding is '
            .'not an accusation; it is the list of accounts for which that decision should have been made '
            .'on purpose. See SEC.AUTH.ROLE_WILDCARD_HOST_PRIVILEGED for the case where it was not.',
            $account,
            $account,
        );
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'reads the account catalog, not the connections: an account that exists and nothing ever authenticates as is the same rows as one in daily use, and which is which is a deployment fact',
            'an address pattern is not reachability. An account with `%` behind a private subnet accepts nothing from outside it, and where the server sits is not a catalog fact',
            'cannot know what the deployment can name instead: a container platform without a stable client address has no narrower host to write, which is a real reason to accept this id rather than a reason to narrow the rule',
        ];
    }
}
