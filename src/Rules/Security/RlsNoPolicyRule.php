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
 * Row-level security is on and the table has no policy at all — the fail-closed accident.
 *
 * Almost never malicious and almost always an operational mistake: somebody switched RLS on, meant to
 * write the policy next, and the deploy went out. What makes it worth its own rule is WHEN it
 * surfaces, which is decided by which role happens to run the query.
 *
 * ## The role-dependence, measured against PostgreSQL 18.4
 *
 * A table with two rows, RLS enabled, no policy:
 *
 * | connecting as | rows returned |
 * |---|---|
 * | the table's OWNER, no `FORCE` | 2 — the owner's exemption applies |
 * | the table's OWNER, with `FORCE` | 0 |
 * | any other role | 0 |
 *
 * So the developer who created the table sees everything working, the migration passes, the seeder
 * passes, and the application returns empty result sets for whichever role it actually connects as.
 * The measurement is in `tests/Postgres/RlsForceRulesTest.php`, against the server rather than
 * against a reading of the manual — a finding that states the exemption wrongly would send somebody
 * to debug their application instead of their policy.
 *
 * ## Why `medium` rather than `high`
 *
 * Nothing is exposed. Data is UNAVAILABLE, which is a different axis: no tenant can read another's
 * rows, because nobody can read any. It is an outage waiting for the first request from a
 * non-owner role, not a disclosure, and the severity says so rather than borrowing weight from the
 * rules around it.
 */
final class RlsNoPolicyRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes
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
        return 'SEC.RLS.NO_POLICY';
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

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

        // No `undetermined` arm: an unreadable table already produces one from
        // SEC.RLS.POLICY_ALWAYS_TRUE, and it is the same reading. Two sentences saying the same
        // catalog could not be read give a reader nothing extra to act on.
        if ($object->getBool('rls_locked_out') !== true) {
            return [];
        }

        $owner = $object->getString('rls_owner');
        $named = $owner === null || $owner === '' ? 'its owner' : $owner;

        // Stated per the table's actual FORCE setting, because the two states behave differently and
        // a finding that described the wrong one would send somebody to debug their application
        // instead of their policy. Measured: owner without FORCE sees every row, owner with FORCE
        // sees none.
        $whoCanRead = $object->getBool('rls_forced') === true
            ? sprintf(
                'to every role INCLUDING %s — FORCE ROW LEVEL SECURITY is set, which removes the '
                .'owner\'s exemption, so the table is unreadable for everybody',
                $named,
            )
            : sprintf(
                'to every role except %s, which still reads all of them — the owner\'s exemption '
                .'applies while FORCE ROW LEVEL SECURITY is not set',
                $named,
            );

        return [RuleVerdict::flag(sprintf(
            'row-level security is enabled on %s and the table has no policy at all, so PostgreSQL '
            .'denies every row %s. Nothing is exposed here — the data is simply unavailable, which is '
            .'why this shape reaches production so often: whoever created the table sees it working, '
            .'the migration passes, and the application connects as a different role and gets empty '
            .'result sets with no error anywhere. Add the policy the table was switched on for, or '
            .'ALTER TABLE %s DISABLE ROW LEVEL SECURITY until there is one.',
            $object->qualifiedName,
            $whoCanRead,
            $object->qualifiedName,
        ))];
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'cannot tell a fail-closed accident from a deliberate lockout. A table with security on and no policy returns nothing to anybody, which is sometimes exactly what a project wants for a table it has stopped using',
            'says nothing about whether the rows would have been correctly separated once a policy exists — that is what the policy-expression rules ask, and they need a policy to ask it of',
        ];
    }
}
