<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The read path is guarded and the WRITE path is not: an explicit `WITH CHECK (true)`.
 *
 * A tenant can only see its own rows and can write a row belonging to anyone. Nothing in the
 * application notices, because the write succeeds; the row simply lands under another tenant's id and
 * is invisible to the one that created it. It surfaces later as data that nobody can account for.
 *
 * ## Why this is a rule of its own rather than a second finding
 *
 * Severity is metadata on the RULE, not on the verdict — a rule has one severity, and this case is
 * genuinely a notch below a policy that admits every row on both paths. Two rules is what expressing
 * that difference honestly costs. It also keeps the guarantee a catalog finding depends on: one
 * verdict per object, so the dedupe cannot swallow the second thing said about one table.
 *
 * ## Why an omitted `WITH CHECK` is not a finding
 *
 * PostgreSQL applies the `USING` expression to the check when no `WITH CHECK` is given. A policy with
 * a real tenant filter and no explicit check is therefore guarded on BOTH paths — and that is how
 * almost everyone writes policies, so reporting it would make this rule noise on the ordinary case.
 * Only an explicit always-true check is a hole, because somebody had to type it.
 */
final class RlsCheckAlwaysTrueRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes
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
        return 'SEC.RLS.CHECK_ALWAYS_TRUE';
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    /**
     * `medium`, one notch under the read-path rule.
     *
     * The read path still holds, so no tenant sees another's data — the exposure is that one can
     * write into another's. That is a real defect and a smaller one than disclosure, and the severity
     * axis exists precisely so the two do not have to be reported at the same weight.
     */
    public function severity(): Severity
    {
        return Severity::Medium;
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

        // No `undetermined` arm here, deliberately: an unreadable table already produces one from
        // SEC.RLS.POLICY_ALWAYS_TRUE, and a second sentence saying the same catalog could not be
        // read adds nothing a reader can act on. The reading is the same reading.
        $offending = $object->getString('rls_always_true_checks') ?? '';

        if ($offending === '') {
            return [];
        }

        $names = explode(',', $offending);
        $quoted = implode(', ', array_map(static fn (string $name): string => '"'.$name.'"', $names));

        return [RuleVerdict::flag(sprintf(
            'the WRITE path of %s is unchecked: %s %s restricts reads correctly, but its WITH CHECK '
            .'expression is a constant that is always true. A tenant sees only its own rows and can '
            .'still insert or update a row carrying somebody else\'s id — the write succeeds, the row '
            .'becomes invisible to whoever created it, and nothing reports an error. Give the check '
            .'the same condition as the filter, or drop the WITH CHECK clause entirely: PostgreSQL '
            .'then applies the USING expression to writes as well, which is what almost every correct '
            .'policy relies on.',
            $object->qualifiedName,
            count($names) === 1 ? 'policy' : 'policies',
            $quoted,
        ))];
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'judges the WRITE path only, and a write nobody is granted is not reachable however permissive the check is — the grant half of the question belongs to the privilege rules',
            'cannot evaluate a check that depends on a runtime value, for the same reason its read-path sibling cannot: the expression is text here and a decision only at execution time',
        ];
    }
}
