<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Severity\Severity;

/**
 * A usable account whose password is stored under a deprecated verifier.
 *
 * `high`, because the account can log in right now and the verifier protecting it is the weaker of
 * the two each engine offers — and on MySQL it is one major release from not working at all.
 */
final class DeprecatedPasswordHashRule extends AbstractDeprecatedPasswordHashRule
{
    public function id(): string
    {
        return 'SEC.AUTH.ROLE_DEPRECATED_PASSWORD_HASH';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    protected function judgesUsableAccounts(): bool
    {
        return true;
    }

    protected function message(string $account, string $driver): string
    {
        return $driver === 'mysql'
            ? sprintf(
                'the password for %s is stored under mysql_native_password. Two things follow, and only '
                .'the first is about cryptography: the verifier is the weaker of the two MySQL offers, and '
                .'the plugin is REMOVED in MySQL 9.0 — this account stops being able to log in at the next '
                .'major, during an upgrade window, with nothing in the connection string to warn anybody. '
                .'ALTER USER %s IDENTIFIED WITH caching_sha2_password BY \'<new password>\' fixes both, and '
                .'it requires the client library to speak the newer handshake; every supported one has for '
                .'years.',
                $account,
                $account,
            )
            : sprintf(
                'the password for %s is stored as an md5 hash. The role NAME is the only salt, so the '
                .'digest is crackable offline and usable as the password itself against any server where a '
                .'role of that name exists — two databases sharing a role name share the exposure. Set '
                .'password_encryption to scram-sha-256 and have the role set its password again, in that '
                .'order: the verifier is written when the password is SET, so changing the setting alone '
                .'leaves this account exactly as it is.',
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
            'the verifier is what the password was stored WITH, not what it is worth. A long random password under a weak hash is a different exposure from a short one, and the strength of the secret is not something a catalog can be asked',
            'cannot say whether the plugin that wrote this verifier is still the server\'s default — a project mid-migration has both kinds stored at once, and only the ones not yet rewritten are reported',
        ];
    }
}
