<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Catalog\Objects\RoleAttribute;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * An account that may create roles — which means it may create accounts.
 *
 * ## What this means on PostgreSQL 16 and later, measured rather than remembered
 *
 * Before 16, `CREATEROLE` was a full escalation: the holder could alter any non-superuser role and
 * grant any membership, so it could simply give itself whatever it wanted. That is the version of this
 * finding most write-ups still describe, and it is no longer what happens.
 *
 * Measured on PostgreSQL 18, as a role holding `CREATEROLE` and nothing else:
 *
 * - creating a new role — **allowed**;
 * - altering a role it did not create — **refused**: *only roles with the CREATEROLE attribute and the
 *   ADMIN option on role "…" may alter this role*;
 * - granting itself a predefined role such as `pg_read_all_data` — **refused**, same shape;
 * - altering a role it created itself — **allowed**, because it holds ADMIN on what it creates.
 *
 * So the honest finding is narrower than the old one and still real: the account cannot take
 * privileges it does not already hold, but it can mint new LOGIN accounts with passwords of its
 * choosing and administer them. That is a way to keep access outside the deployment process, and it
 * survives a password rotation on the account everybody knows about.
 */
final class CreateRoleAttributeRule extends AbstractRoleAttributeRule
{
    public function id(): string
    {
        return 'SEC.PRIV.ROLE_CREATEROLE';
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    protected function attribute(): RoleAttribute
    {
        return RoleAttribute::CreateRole;
    }

    /**
     * A superuser holds this by definition, and `SEC.PRIV.ROLE_SUPERUSER` already says the larger thing.
     * Three findings about one account would bury the one that matters under two that follow from it.
     */
    #[Override]
    protected function supersededBy(SchemaObject $object): bool
    {
        if ($this->holds($object, 'attributes') && str_contains($object->getString('attributes') ?? '', RoleAttribute::Superuser->value)) {
            return true;
        }

        return $this->holds($object, 'reachable_attributes') && str_contains($object->getString('reachable_attributes') ?? '', RoleAttribute::Superuser->value);
    }

    protected function heldMessage(string $role): string
    {
        return sprintf(
            '%s holds CREATEROLE, so it can create login accounts and administer the ones it creates. '
            .'Since PostgreSQL 16 it can no longer take privileges it does not already hold — altering a '
            .'role it did not create is refused — so this is not the blanket escalation older write-ups '
            .'describe. What it still is: a way to keep access outside your deployment process, with a '
            .'password nobody rotates. ALTER ROLE %s NOCREATEROLE unless creating accounts is genuinely '
            .'this role\'s job.',
            $role,
            $role,
        );
    }

    protected function reachableMessage(string $role, string $path): string
    {
        return sprintf(
            '%s can assume CREATEROLE with one SET ROLE, through %s — so it can create login accounts '
            .'and administer them, without holding the attribute itself. Revoke the membership that '
            .'leads there rather than the attribute at the end of it.',
            $role,
            $path,
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
            'an account that may create roles may create one for itself with different privileges, so this is reported as a path rather than as a state. Whether anybody has walked it is in the server\'s logs, not its catalog',
        ];
    }
}
