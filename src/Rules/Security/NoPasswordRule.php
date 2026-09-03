<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Severity\Severity;

/**
 * A usable MySQL account with no password at all.
 *
 * `critical`, and it is the shortest path into a database there is: no cracking, no capture, no
 * interception — reach the port, know the name, you are in. Every other account finding in this
 * package describes something an attacker still has to do work to exploit.
 */
final class NoPasswordRule extends AbstractNoPasswordRule
{
    public function id(): string
    {
        return 'SEC.AUTH.ROLE_NO_PASSWORD';
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    protected function judgesUsableAccounts(): bool
    {
        return true;
    }

    protected function message(string $account): string
    {
        return sprintf(
            '%s can log in and has no password stored at all. Anyone who can reach this server and knows '
            .'the account name is already in — there is nothing to crack, capture or intercept. Set one '
            .'with ALTER USER %s IDENTIFIED BY \'<new password>\', or drop the account if nothing uses it. '
            .'If the credential is meant to live outside the database, say so explicitly by moving the '
            .'account to the authentication plugin that holds it (auth_socket, PAM, LDAP); an empty '
            .'password under a password plugin is not the same arrangement and this server treats it as a '
            .'valid login.',
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
            'no password in the catalog does not always mean no authentication: an account may authenticate through a plugin that keeps its secret elsewhere, and the catalog shows the empty verifier either way',
        ];
    }
}
