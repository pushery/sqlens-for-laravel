<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A routine that runs as its owner and lets the CALLER decide what its names mean.
 *
 * This is the exploitable one, and the mechanism is worth stating exactly because it does not look
 * like an opening from the outside.
 *
 * A `SECURITY DEFINER` routine runs with the privileges of its owner. Inside it, an unqualified name
 * — `now()`, `users`, `crypt()` — is resolved through the `search_path` that is in effect, and unless
 * the routine pins its own, that is the CALLER's. So a caller who can create a schema puts one ahead
 * of the routine's, defines a function with the name the routine uses, and calls the routine. The
 * routine calls the impostor. As the owner.
 *
 * `EXECUTE` on such a routine is therefore not "may run this function". It is "may run arbitrary code
 * as the owner" — and the owner is usually the role that owns the schema, which on an ordinary Laravel
 * deployment owns everything.
 *
 * ## Why the fix is one clause and not a redesign
 *
 * A `SET search_path` clause on the routine — an explicit list, the catalog schema, or the empty string
 * — makes it resolve its own names. It is one line on the function, it changes nothing about what the function does, and
 * it closes the whole path.
 */
final class RoutineDefinerMutablePathRule extends AbstractRoutineRule
{
    public function id(): string
    {
        return 'SEC.PRIV.ROUTINE_DEFINER_MUTABLE_PATH';
    }

    /**
     * `critical`, and the word is doing work rather than decorating: the finding is not "a privilege
     * is wider than it needs to be", it is "anyone holding EXECUTE can run code as the owner".
     */
    public function severity(): Severity
    {
        return Severity::Critical;
    }

    protected function appliesToPinnedPath(): bool
    {
        return false;
    }

    protected function message(SchemaObject $object): string
    {
        return sprintf(
            '%s runs with the privileges of %s (SECURITY DEFINER) and does not pin its own search_path, so '
            .'the unqualified names inside it resolve through the CALLER\'s. Anyone who can create a schema '
            .'and holds EXECUTE on this routine can put their own function ahead of the one it means to '
            .'call — and it will be called as %s. Pin the routine\'s own search path with a SET clause — an '
            .'explicit schema list, the catalog schema, or the empty string to force every name to be '
            .'qualified; it changes nothing about what the routine does and closes the path entirely.',
            $object->qualifiedName,
            $object->getString('owner') ?? 'its owner',
            $object->getString('owner') ?? 'its owner',
        );
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'reads the routine\'s SIGNATURE and its declared path, never its body. A routine whose every reference is already schema-qualified is safe in practice and is still reported, because whether the next edit stays qualified is not something the catalog can promise',
            'a mutable path is only exploitable by somebody who can create an object in a schema the caller reaches — which is a privilege question, and one the grant rules answer separately',
        ];
    }
}
