<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Severity\Severity;

/**
 * An account that may connect from any host AND can do anything once it does.
 *
 * `high`. Neither half is remarkable alone: plenty of accounts are reachable from anywhere for good
 * reasons, and every server has privileged accounts. Together they are the shape an intrusion takes
 * — one guessed or leaked credential, reachable from the whole internet, with nothing left to
 * escalate to afterwards.
 */
final class WildcardHostPrivilegedRule extends AbstractWildcardHostRule
{
    public function id(): string
    {
        return 'SEC.AUTH.ROLE_WILDCARD_HOST_PRIVILEGED';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    protected function judgesPrivilegedAccounts(): bool
    {
        return true;
    }

    protected function message(string $account): string
    {
        return sprintf(
            '%s may connect from ANY host AND holds far-reaching privileges. Either half alone is ordinary; '
            .'together they leave nothing between the whole network and an account with nothing above it to '
            .'escalate to — one leaked or guessed credential is the entire attack. Two fixes, and they are '
            .'independent, so doing one is already progress: narrow the host to the network the client '
            .'really comes from, and take away the privileges this account does not use — a deployment '
            .'account rarely needs SUPER, FILE or the whole of *.*. If it genuinely does, keep the '
            .'privileges and narrow the host, because the host is the half nobody has to reason about at '
            .'run time.',
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
            'both halves are read from the catalog and neither is read from the network: this is the account that would be worst to lose, not evidence that anything has reached it',
            'the privilege half follows grants the server records, not memberships resolved through a chain of roles — an account privileged only by inheritance is the sibling rule\'s subject',
        ];
    }
}
