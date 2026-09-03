<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Severity\Severity;

/**
 * A grant that hands on the power to CHANGE THE SCHEMA.
 *
 * `high`. The difference from its sibling is not degree: a re-grantable data privilege widens who
 * can read or write what exists, and a re-grantable structural one widens who can decide what
 * exists at all — including who can create the objects a later audit would have to notice.
 */
final class GrantOptionStructuralRule extends AbstractGrantOptionRule
{
    public function id(): string
    {
        return 'SEC.PRIV.GRANT_OPTION_STRUCTURAL';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    protected function judgesStructuralGrants(): bool
    {
        return true;
    }

    protected function message(string $grantee, string $target): string
    {
        return sprintf(
            '%s may hand on the power to CHANGE the schema of %s, not merely to read or write what is in it '
            .'(WITH GRANT OPTION on a structural privilege). That is the combination worth acting on: the '
            .'account can grant a second account the right to create, alter or drop objects, and objects '
            .'created that way look exactly like the ones anybody else made. A migration account holding '
            .'this is common and often deliberate; an application account holding it is almost never '
            .'intended. REVOKE GRANT OPTION FOR … ON %s FROM %s keeps the account working and takes away '
            .'only its ability to widen the server.',
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
            'the structural half is graded apart because schema change is not data access, and the two are silenced separately on purpose — a project accepting one is not accepting the other',
        ];
    }
}
