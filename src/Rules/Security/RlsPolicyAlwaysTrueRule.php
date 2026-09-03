<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Catalog\Objects\ReadabilityState;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Row-level security is on, and a policy lets every row through anyway.
 *
 * This is the worst of the four RLS states to be in, because it is the one that looks correct from
 * every angle a review reaches: the table has RLS enabled, it has a policy, `\d+` shows both, and the
 * separation does not exist. `USING (true)` is what somebody writes to get a feature working and
 * intends to come back to.
 *
 * ## One always-true policy is enough, and that is the finding
 *
 * Permissive policies are OR-ed. A table with a careful tenant policy AND one `USING (true)` policy is
 * exactly as exposed as a table with only the second — the careful one contributes nothing to the
 * outcome. So the finding is about the offending policy rather than about the set, and it says which
 * one, because the remediation is to open that policy and no other.
 *
 * A restrictive policy cannot produce this state: it is AND-ed and can only narrow. Counting one would
 * report a table that is more protected than the rule understands.
 *
 * ## The honesty boundary is the point of this rule, not a caveat on it
 *
 * SQLens recognizes the CONSTANT forms the server deparses an always-true filter into — measured, not
 * assumed. Anything with a function call, a `current_setting()` comparison or a subquery is a filter
 * it does not evaluate, and it says nothing about those rather than guessing. A rule that tried to
 * decide whether an arbitrary expression can ever be false would be wrong occasionally and confident
 * always, which in a security suite is worse than silent.
 */
final class RlsPolicyAlwaysTrueRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes
{
    /**
     * Tables only — a run that read none produced no subject for this rule, and the report has to be
     * able to say so rather than let the silence read as a clean answer.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Table];
    }

    public function id(): string
    {
        return 'SEC.RLS.POLICY_ALWAYS_TRUE';
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    /**
     * `high`, for the same reason as a table with RLS switched off: the isolation the project
     * configured does not exist. It is arguably worse here — the table carries every visible sign of
     * being protected — but the severity axis has no rung above `high` short of `critical`, which is
     * reserved for what breaks a database rather than what exposes it.
     */
    public function severity(): Severity
    {
        return Severity::High;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Table || $object->getBool('rls_scoped') !== true) {
            return [];
        }

        if ($object->getString('readability') === ReadabilityState::Unreadable->value) {
            return [RuleVerdict::undetermined(
                sprintf('the policies on %s could not be read, so whether one of them admits every row is unknown', $object->qualifiedName),
                UndeterminedReason::MissingPrivilege,
            )];
        }

        $offending = $object->getString('rls_always_true_policies') ?? '';

        if ($offending === '') {
            return [];
        }

        // ONE verdict naming every offending policy, never one per policy: a catalog finding is
        // located at the OBJECT, so a second verdict about the same table is dropped by the dedupe
        // without a word — and the policy nobody was told about goes on admitting everything.
        return [RuleVerdict::flag(sprintf(
            'row-level security is enabled on %s, and the policy %s admits every row: its filter is a '
            .'constant that is always true, so the table is exactly as exposed as one with no policy '
            .'at all. Permissive policies are OR-ed, so this holds even if another policy on the same '
            .'table filters correctly — that one contributes nothing while this one is present. '
            .'Replace the filter with the tenant condition, for example '
            .'USING (tenant_id = current_setting(\'app.tenant\')::uuid), or drop the policy if it was '
            .'a placeholder.',
            $object->qualifiedName,
            $this->named($offending),
        ))];
    }

    /**
     * `policy "p"` or `policies "a", "b"` — quoted, because a policy name can contain anything and an
     * unquoted list of them is unreadable the first time somebody names one `tenant read`.
     */
    private function named(string $joined): string
    {
        $names = explode(',', $joined);
        $quoted = implode(', ', array_map(static fn (string $name): string => '"'.$name.'"', $names));

        return count($names) === 1 ? 'policy '.$quoted : 'policies '.$quoted;
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'reads the policy EXPRESSION as text, and an expression that looks unconditional may be sitting on a table whose access is already restricted by grants — the two mechanisms compose, and this rule sees one of them',
            'cannot evaluate a policy that depends on a runtime value. `current_setting(\'app.tenant\')` is restrictive or vacuous depending on what the session sets, and no catalog read decides that',
        ];
    }
}
