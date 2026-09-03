<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The one condition the two `FORCE` rules share, and the sentence they both append.
 *
 * They differ in exactly one thing — whether the audited connection owns the table — and that
 * difference is what puts them at different severities. Everything before it is identical, and
 * identical logic written twice is logic that stops being identical the first time one copy is fixed.
 *
 * Not a base class: these are two rules with different ids, different documentation pages and
 * different severities, and inheritance between them would suggest a hierarchy that does not exist.
 */
final readonly class RlsForceScope
{
    /**
     * Whether this subject is a scoped table whose policies are being bypassed by its owner.
     *
     * The policy count is part of it rather than an afterthought: a table with RLS on and NO policy is
     * a different finding ({@see RlsNoPolicyRule}), and "your policies are being bypassed" is not a
     * true sentence about a table that has none.
     */
    public static function applies(SchemaObject $object): bool
    {
        return $object->type === SchemaObjectType::Table
            && $object->getBool('rls_scoped') === true
            && $object->getBool('rls_enabled') === true
            && $object->getBool('rls_forced') === false
            && ($object->getInt('rls_policy_count') ?? 0) > 0;
    }

    /**
     * The cross-reference, when an account bypasses row-level security outright.
     *
     * Appended rather than reported separately: `FORCE` closes the owner's exemption and does nothing
     * about `BYPASSRLS`, so a finding that stopped at "add FORCE" would promise a protection that
     * account still walks straight through.
     */
    public static function bypassNote(SchemaObject $object): string
    {
        $bypassing = $object->getString('rls_bypassing_roles') ?? '';

        if ($bypassing === '') {
            return '';
        }

        return sprintf(
            ' Note that FORCE does not affect %s, which %s row-level security outright — see '
            .'SEC.PRIV.ROLE_BYPASSRLS.',
            $bypassing,
            str_contains($bypassing, ',') ? 'bypass' : 'bypasses',
        );
    }
}
