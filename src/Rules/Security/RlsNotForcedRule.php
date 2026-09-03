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
 * The policies are correct, and they do not apply to the connection this audit ran as.
 *
 * `ENABLE ROW LEVEL SECURITY` exempts the table's OWNER. A Laravel application usually connects as the
 * role that owns its tables — one connection in `config/database.php`, used by migrations and by
 * requests alike — so every policy on the database is bypassed by the application itself, and nothing
 * in the policy definitions, the catalog listing or a code review says so.
 *
 * Measured against PostgreSQL 18.4, a table with two rows, RLS on and `USING (tenant_id = 1)`:
 *
 * | connecting as the owner | rows returned |
 * |---|---|
 * | without `FORCE` | 2 — the policy is not applied |
 * | with `FORCE` | 1 — the policy is applied |
 *
 * ## Why this is the case that gets its own rule and its own severity
 *
 * Because it is the normal Laravel arrangement, not the textbook one. The guardrail on the ticket says
 * it plainly: migration and runtime role are often identical and are also the owner. A rule that only
 * reported the missing `FORCE` in the abstract would rate the everyday, dangerous case the same as the
 * theoretical one — so the everyday case is this rule, at `high`, and the other one is
 * {@see RlsOwnerUnrestrictedRule} at `medium`. Severity is metadata on the RULE; two rules is what
 * expressing that difference honestly costs.
 *
 * ## Silent when there is nothing to force
 *
 * A table with no policy is reported by {@see RlsNoPolicyRule} and not here: "your policies are being
 * bypassed" is not a true sentence about a table that has none, and two findings about one table bury
 * the one that names the actual problem.
 */
final class RlsNotForcedRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes
{
    /**
     * Tables only — and this rule is the one that proved a source-scanning guard cannot see that.
     *
     * Its narrowing lives one layer down, in {@see RlsForceScope::applies()}, so the regex that made
     * its five siblings declare found nothing here and asked nothing of it. The result was the exact
     * shape {@see \\Pushery\\SQLens\\Audit\\RuleEvaluation} calls harmful: with no declaration it counted as
     * evaluated by any subject at all, so a run that read one role and zero tables still reported
     * this check as having run.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Table];
    }

    public function id(): string
    {
        return 'SEC.RLS.NOT_FORCED';
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    /**
     * `high`: the tenant isolation this project configured does not apply to the connection its
     * application uses. The policies exist, they are correct, and they are not consulted.
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
        if (! RlsForceScope::applies($object) || $object->getBool('rls_owner_is_connection') !== true) {
            return [];
        }

        $owner = $object->getString('rls_owner');

        return [RuleVerdict::flag(sprintf(
            'row-level security is enabled on %s and not FORCED, and this audit connected as %s, which '
            .'owns the table: the owner is exempt from every policy on it, so the tenant separation '
            .'you configured is not applied to the very connection your application uses. Nothing in '
            .'the policies says so — reviewing them comes back correct. ALTER TABLE %s FORCE ROW LEVEL '
            .'SECURITY makes them apply to the owner as well. Verify the application still returns the '
            .'rows it should afterwards: on this table it currently returns more.%s',
            $object->qualifiedName,
            $owner === null || $owner === '' ? 'the table\'s owner' : $owner,
            $object->qualifiedName,
            RlsForceScope::bypassNote($object),
        ))];
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'FORCE only changes anything for the table\'s OWNER, so a project whose application never connects as the owner is not exposed by its absence — and which role the application uses is not something a catalog read can answer',
            'reads the flag, not the connection: it cannot say whether the role this audit ran as is the same one the application uses, and the two are frequently different by design',
        ];
    }
}
