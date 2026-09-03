<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A routine that runs as its owner, correctly — reported anyway, and on purpose.
 *
 * It pins its `search_path`, so the path {@see RoutineDefinerMutablePathRule} exists for is closed.
 * This is the recommended construction: it is how a low-privilege application is given one narrow,
 * audited way into something it otherwise could not touch, and a project that uses it has done the
 * right thing.
 *
 * ## Why a correct construction is still a finding
 *
 * Because of what it does to every OTHER judgment about the database. `EXECUTE` on this routine is
 * not an ordinary privilege — it is a bounded loan of the owner's rights, and a reviewer looking at a
 * grant list has no way to see that from the grant. Nor does the least-privilege rule: a runtime role
 * holding only `EXECUTE` looks minimal and may reach further than any of its other grants allow.
 *
 * So this is an inventory entry rather than an accusation, and its severity says so. Its job is that
 * nobody is surprised: when somebody asks "what can the application actually do", these routines are
 * part of the answer, and a report that listed only the grants would be missing the part that matters
 * most.
 */
final class RoutineDefinerRule extends AbstractRoutineRule
{
    public function id(): string
    {
        return 'SEC.PRIV.ROUTINE_DEFINER';
    }

    /**
     * `low`: nothing here is wrong. It is on the report because `EXECUTE` on it means more than
     * `EXECUTE` usually does, and a project that raises `security.min_severity` past this is saying it
     * already knows — which is a decision it is entitled to make once, rather than a finding it has to
     * dismiss on every run.
     */
    public function severity(): Severity
    {
        return Severity::Low;
    }

    protected function appliesToPinnedPath(): bool
    {
        return true;
    }

    protected function message(SchemaObject $object): string
    {
        return sprintf(
            '%s runs with the privileges of %s (SECURITY DEFINER) and pins its search_path (%s), which is '
            .'the construction done right — the escalation path SEC.PRIV.ROUTINE_DEFINER_MUTABLE_PATH '
            .'reports is closed here. It is listed because EXECUTE on it is a bounded loan of %s\'s '
            .'rights rather than an ordinary privilege: a role holding only EXECUTE can look minimal and '
            .'still reach further than its other grants allow. Confirm the grant list on this routine is '
            .'the one you meant.',
            $object->qualifiedName,
            $object->getString('owner') ?? 'its owner',
            $object->getString('settings') ?? 'set',
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
            'reports a routine that is CORRECT, on purpose: a definer routine is a deliberate escalation boundary, and the finding exists so somebody confirms it was deliberate. Silencing it with a reason is the expected outcome rather than a failure',
        ];
    }
}
