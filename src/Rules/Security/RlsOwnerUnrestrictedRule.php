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
 * The policies do not apply to the table's owner — and this audit is not that role.
 *
 * The same missing `FORCE ROW LEVEL SECURITY` as {@see RlsNotForcedRule}, seen from the other side.
 * The connection SQLens audited with is restricted by the policies exactly as intended; the owner is
 * not, and somebody uses that role: migrations, a maintenance command, a console session, the deploy
 * pipeline. Every one of those reads and writes across tenants without a policy being consulted.
 *
 * ## Why `medium` here and `high` there
 *
 * Not because the mechanism is weaker — it is identical — but because of who reaches it. There, the
 * exemption applies to the connection the application serves requests with, so ordinary traffic
 * bypasses the isolation. Here it applies to a role a person or a job uses deliberately, which is a
 * smaller and more supervised surface. Severity is metadata on the RULE, so the difference cannot live
 * on the verdict; two rules is what saying it honestly costs.
 *
 * A run whose reading could not establish the connecting role reports through THIS rule rather than
 * the other one — the weaker claim is the one that stays true when the stronger cannot be checked.
 */
final class RlsOwnerUnrestrictedRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes
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
        return 'SEC.RLS.OWNER_UNRESTRICTED';
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
        if ($object->type !== SchemaObjectType::Table || ! RlsForceScope::applies($object)) {
            return [];
        }

        // The other side of one condition, never both: a table whose owner IS this connection is
        // reported by SEC.RLS.NOT_FORCED at high, and reporting it twice would put the smaller
        // sentence next to the larger one about the same table.
        if ($object->getBool('rls_owner_is_connection') === true) {
            return [];
        }

        $owner = $object->getString('rls_owner');

        return [RuleVerdict::flag(sprintf(
            'row-level security is enabled on %s and not FORCED, so its owner%s is exempt from every '
            .'policy on it. This audit did not connect as that role, so the application path is '
            .'restricted as intended — but migrations, maintenance commands and console sessions '
            .'usually run as the owner, and each of those reads and writes across tenants with no '
            .'policy consulted and nothing reported. ALTER TABLE %s FORCE ROW LEVEL SECURITY applies '
            .'the policies to the owner as well.%s',
            $object->qualifiedName,
            $owner === null || $owner === '' ? '' : ' ('.$owner.')',
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
            'the exposure depends on WHO connects, and the catalog does not record that. An owner-unrestricted table is only reachable if something actually connects as the owner — which is a deployment fact, not a schema fact',
            'cannot see a role\'s memberships in full: a role that inherits ownership through a group is the owner for this purpose, and following that chain is the audit suite\'s separate question',
        ];
    }
}
