<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Severity\Severity;

/**
 * An anonymous account that does at least have a password.
 *
 * `high`. The password is real protection, so this is not the open door its sibling describes — but
 * the account still catches every connection made under a name the server does not know, and
 * whatever it can do, those connections can do. An account nobody named is an account nobody audits.
 */
final class AnonymousAccountRule extends AbstractAnonymousAccountRule
{
    public function id(): string
    {
        return 'SEC.AUTH.ROLE_ANONYMOUS';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    protected function judgesPasswordlessAccounts(): bool
    {
        return false;
    }

    protected function message(string $account): string
    {
        return sprintf(
            '%s is an ANONYMOUS account: its user name is empty, which does not mean unused — it means it '
            .'matches ANY name the server does not otherwise know, from a host matching its pattern. Every '
            .'mistyped user name and every stale credential from that host lands here and is authenticated, '
            .'with whatever privileges this account holds. It does have a password, which is the only reason '
            .'this is not the open door SEC.AUTH.ROLE_NO_PASSWORD describes. MySQL has not shipped anonymous '
            .'accounts for many years, so this is almost certainly carried forward from an older server: '
            .'DROP USER %s unless something genuinely depends on it, and if something does, that dependency '
            .'is worth writing down.',
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
            'an anonymous account is reachable by anyone who can reach the server at all, so what it can DO decides how much this matters — and that is the privilege rules\' question, deliberately not answered twice here',
        ];
    }
}
