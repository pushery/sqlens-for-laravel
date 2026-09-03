<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Catalog\Objects\RoleAttribute;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * An account that row-level security does not apply to.
 *
 * `BYPASSRLS` is the quietest of the three attributes and the one most likely to be a surprise. RLS
 * policies are the mechanism a multi-tenant application relies on to keep one tenant's rows away from
 * another's; an account holding this reads and writes every row regardless, and nothing in the policy
 * definitions says so. The audit of the policies comes back correct, and it is beside the point.
 *
 * ## Why `high`, even though this rule cannot see the policies
 *
 * The first draft rated it `medium`, reasoning that on a database with no RLS the attribute bypasses
 * nothing. That reasoning is right about the consequence and wrong about the risk, for one reason:
 * NOBODY SETS THIS BY ACCIDENT. `BYPASSRLS` is not a default, not a side effect of a framework, and
 * not something a managed provider hands out — an account has it because somebody typed it. So the
 * finding is rare, which is exactly the shape a `high` should have, and where it does fire the
 * protection a project believes it has is not there.
 *
 * The finding still states the limit rather than overclaiming: this rule reads roles, not policies, so
 * it says WHAT TO CHECK instead of asserting that a particular table is exposed.
 */
final class BypassRlsRoleRule extends AbstractRoleAttributeRule
{
    public function id(): string
    {
        return 'SEC.PRIV.ROLE_BYPASSRLS';
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    protected function attribute(): RoleAttribute
    {
        return RoleAttribute::BypassRls;
    }

    /**
     * A superuser bypasses RLS whether or not it carries the attribute, and is already reported.
     *
     * The superuser finding carries the cross-reference, so this stays silent rather than saying the
     * same thing one notch quieter — two findings about one account bury the one that matters.
     */
    #[Override]
    protected function supersededBy(SchemaObject $object): bool
    {
        return str_contains($object->getString('attributes') ?? '', RoleAttribute::Superuser->value)
            || str_contains($object->getString('reachable_attributes') ?? '', RoleAttribute::Superuser->value);
    }

    protected function heldMessage(string $role): string
    {
        return sprintf(
            '%s holds BYPASSRLS, so row-level security does not apply to it: it reads and writes every '
            .'row of every table with a policy, and nothing in the policies themselves says so. If this '
            .'database uses RLS to separate tenants, an audit of the policies comes back correct and is '
            .'beside the point for this account. ALTER ROLE %s NOBYPASSRLS unless it exists precisely to '
            .'read across tenants.',
            $role,
            $role,
        );
    }

    protected function reachableMessage(string $role, string $path): string
    {
        return sprintf(
            '%s can assume BYPASSRLS with one SET ROLE, through %s — one statement away from reading '
            .'every row of every table with a policy. Revoke the membership that leads there rather than '
            .'the attribute at the end of it.',
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
            'BYPASSRLS matters exactly as much as the policies it bypasses: on a database with no row-level security it changes nothing, and whether the tables that need it have it is the RLS family\'s question',
        ];
    }
}
