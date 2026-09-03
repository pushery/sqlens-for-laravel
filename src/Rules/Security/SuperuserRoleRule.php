<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Catalog\Objects\RoleAttribute;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Severity\Severity;

/**
 * An account that is a superuser, or one `SET ROLE` away from being one.
 *
 * Superuser is not a strong permission — it is the ABSENCE of permission checks. Row-level security
 * does not apply to it, `GRANT` and `REVOKE` do not constrain it, and it can read and write every file
 * the database process can. Every other finding this suite produces is a statement about a boundary,
 * and this one says there is no boundary to state anything about.
 *
 * Which is why it is `high` while its two siblings are `medium`: they describe a way to acquire more
 * power, and this describes already having all of it.
 *
 * ## The reachable case is the common one
 *
 * Almost nobody sets `SUPERUSER` on an application role. What happens instead is that the application
 * role is granted a role that has it — often the bootstrap role, often during a migration that needed
 * it once — and PostgreSQL does not inherit ATTRIBUTES through membership, so `\du` shows the
 * application role as unremarkable. It is one `SET ROLE` from everything, and nothing in the usual
 * places says so.
 */
final class SuperuserRoleRule extends AbstractRoleAttributeRule
{
    public function id(): string
    {
        return 'SEC.PRIV.ROLE_SUPERUSER';
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
        return RoleAttribute::Superuser;
    }

    protected function heldMessage(string $role): string
    {
        return sprintf(
            '%s is a SUPERUSER. That is not a strong permission but the absence of permission checks: '
            .'row-level security does not apply to it, GRANT and REVOKE do not constrain it, and it can '
            .'read and write every file the database process can. If this is the role an application '
            .'connects as, every other protection in this database is advisory. Create a role with the '
            .'privileges the application actually needs and point the connection at it: '
            .'ALTER ROLE %s NOSUPERUSER once nothing depends on it. This finding also stands in for '
            .'SEC.PRIV.ROLE_BYPASSRLS and SEC.PRIV.ROLE_CREATEROLE: a superuser holds both by definition, '
            .'so they are not reported separately for this account.',
            $role,
            $role,
        );
    }

    protected function reachableMessage(string $role, string $path): string
    {
        return sprintf(
            '%s can become a SUPERUSER with one SET ROLE, through %s. PostgreSQL does not inherit role '
            .'ATTRIBUTES through membership, so this account looks unremarkable in \\du and in pg_roles — '
            .'and is one statement away from an account that no permission check applies to. Revoke the '
            .'membership that leads there rather than the attribute at the end of it. This finding also '
            .'stands in for SEC.PRIV.ROLE_BYPASSRLS and SEC.PRIV.ROLE_CREATEROLE, which follow from it.',
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
            'covers the attribute and the one SET ROLE away from it. A path longer than one step — a chain of memberships ending at a superuser — is not followed here, and a project with deep role nesting should read this as a floor rather than as the whole answer',
        ];
    }
}
