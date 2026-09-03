<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Severity\Severity;

/**
 * A data grant an account may hand on.
 *
 * `medium`. What is handed on is access to data rather than the power to reshape the schema, so the
 * blast radius is bounded by what this grant already covers — but the account can still widen the
 * server's access surface without anybody granting anything, which is what makes it worth a line.
 */
final class GrantOptionRule extends AbstractGrantOptionRule
{
    public function id(): string
    {
        return 'SEC.PRIV.GRANT_OPTION';
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    protected function judgesStructuralGrants(): bool
    {
        return false;
    }

    protected function message(string $grantee, string $target): string
    {
        return sprintf(
            '%s may hand its access to %s on to other accounts (WITH GRANT OPTION). Every other limit on '
            .'this server becomes voluntary at that point: the account can create a second one holding the '
            .'same access, and the second one carries no note about where it came from — so an audit run '
            .'tomorrow sees a plain account and not the path that made it. Administrative accounts hold '
            .'this on purpose and it is not a defect there; what this finding gives you is the list of '
            .'accounts for which it should have been a decision. Revoke it with '
            .'REVOKE GRANT OPTION FOR … ON %s FROM %s, which leaves the access itself intact.',
            $grantee,
            $target,
            $target,
            $grantee,
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
            'reports the ability to hand the privilege on, not any use of it: whether anything HAS been granted onward is a second question, and the catalog answers it only for grants that already happened',
        ];
    }
}
