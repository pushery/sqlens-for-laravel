<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Severity\Severity;

/**
 * An anonymous account with no password at all.
 *
 * `critical`, and it is the worst account state this package can report: no name is needed, and no
 * password either. Anyone who can reach the port from a matching host is inside, under a name they
 * chose themselves.
 *
 * It carries the whole finding on its own — {@see AbstractNoPasswordRule} stands down on an
 * anonymous account — because this is ONE fact, and two ids about one account read as two problems.
 */
final class AnonymousAccountNoPasswordRule extends AbstractAnonymousAccountRule
{
    public function id(): string
    {
        return 'SEC.AUTH.ROLE_ANONYMOUS_NO_PASSWORD';
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    protected function judgesPasswordlessAccounts(): bool
    {
        return true;
    }

    protected function message(string $account): string
    {
        return sprintf(
            '%s is an ANONYMOUS account with NO PASSWORD — the two worst account states at once, and the '
            .'shortest way into this server that exists. The empty user name matches any name the server does '
            .'not otherwise know, so a client from a matching host picks whatever name it likes; the empty '
            .'credential means nothing is then asked of it. There is no step to get past. DROP USER %s. '
            .'MySQL has not shipped an account like this in many years, so it is carried forward from an '
            .'older server rather than something anyone configured on purpose — check what it can reach '
            .'before you assume the exposure was small.',
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
            'reports the account, never an attempt: whether anything has actually connected through it is in the server\'s logs rather than its catalog, and this package reads catalogs',
        ];
    }
}
