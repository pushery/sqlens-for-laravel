<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Severity\Severity;

/**
 * A LOCKED account whose password is stored under a deprecated verifier.
 *
 * `low`, and reported rather than skipped. It cannot log in today, so it is not the finding to fix
 * first — but unlocking it is one statement, and an account that comes back comes back carrying the
 * verifier it was locked with. A rule that stayed silent here would make "locked" look like a fix.
 */
final class DeprecatedPasswordHashLockedRule extends AbstractDeprecatedPasswordHashRule
{
    public function id(): string
    {
        return 'SEC.AUTH.ROLE_DEPRECATED_PASSWORD_HASH_LOCKED';
    }

    public function severity(): Severity
    {
        return Severity::Low;
    }

    protected function judgesUsableAccounts(): bool
    {
        return false;
    }

    protected function message(string $account, string $driver): string
    {
        return sprintf(
            '%s cannot log in as it stands — it is locked or its password has expired — and the password '
            .'it still carries is stored under a deprecated verifier (%s). That is why this is reported at '
            .'low rather than skipped: locking an account is not fixing it, unlocking is one statement, and '
            .'the account comes back with exactly the verifier it went away with. Give it a current one '
            .'while it is out of use, or drop it if nothing needs it. See '
            .'SEC.AUTH.ROLE_DEPRECATED_PASSWORD_HASH for what to set and why.',
            $account,
            $driver === 'mysql' ? 'mysql_native_password, which MySQL 9.0 removes entirely' : 'md5, salted with the role name and nothing else',
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
            'the locked/unlocked split is the whole reason this id is separate from its sibling, and it rests on the server\'s own flag. An account locked by something OUTSIDE the server — a network rule, a proxy refusing it — reads as usable here',
            'a locked account keeps its verifier, so unlocking it later restores exactly the weakness reported here — which is why this is a finding at all rather than a state to ignore',
        ];
    }
}
