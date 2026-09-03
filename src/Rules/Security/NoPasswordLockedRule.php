<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Severity\Severity;

/**
 * A LOCKED MySQL account with no password at all.
 *
 * `low`, and reported rather than skipped. It cannot be used as it stands — but unlocking is one
 * statement, and what comes back is an account anyone who knows its name can log into. A rule that
 * said nothing here would let `ACCOUNT LOCK` read as a fix for a missing password, which it is not:
 * it is a door held shut by a latch somebody can lift.
 */
final class NoPasswordLockedRule extends AbstractNoPasswordRule
{
    public function id(): string
    {
        return 'SEC.AUTH.ROLE_NO_PASSWORD_LOCKED';
    }

    public function severity(): Severity
    {
        return Severity::Low;
    }

    protected function judgesUsableAccounts(): bool
    {
        return false;
    }

    protected function message(string $account): string
    {
        return sprintf(
            '%s cannot log in as it stands — it is locked or its password has expired — and it has no '
            .'password stored at all. That combination is why this is reported rather than skipped: the '
            .'lock is the only thing standing in the way, ALTER USER … ACCOUNT UNLOCK removes it in one '
            .'statement, and the account comes back with nothing protecting it. Give it a password while '
            .'it is out of use, or drop it if nothing needs it. See SEC.AUTH.ROLE_NO_PASSWORD for what an '
            .'open account costs.',
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
            'the locked/unlocked split is the whole reason this id is separate from its sibling, and it rests on the server\'s own flag. An account locked by something OUTSIDE the server — a network rule, a proxy refusing it — reads as usable here',
            'unlocking restores the account exactly as it is — with no password. The finding is about what the account WOULD be, which is the only useful thing to say about a state somebody can undo with one statement',
        ];
    }
}
