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
 * An account holding a privilege that administers the SERVER rather than a database.
 *
 * ## Why this cannot be a check for `SUPER`
 *
 * It is the obvious implementation and it is the wrong one. MySQL deprecated `SUPER` in 8.0 and
 * split its powers across a family of dynamic privileges, so on a correctly configured 8.4 an
 * account can change every global variable, kill anybody's session and run code as another user
 * without holding `SUPER` at all. A rule looking only for that name comes back empty and reads
 * exactly like a rule with nothing to report.
 *
 * So the list lives in a shipped artifact ({@see MysqlAdminPrivileges}) and is reconciled against a
 * real server by a test that asks MySQL to accept every name. That reconciliation is not ceremony:
 * on its first run it rejected `SET_USER_ID`, which 8.4 refuses outright — the privilege was split
 * into `SET_ANY_DEFINER` and `ALLOW_NONEXISTENT_DEFINER`, and the rule would have matched nothing.
 *
 * ## What it deliberately does not judge
 *
 * `GRANT OPTION` is in the same vocabulary and is owned by {@see AbstractGrantOptionRule}. It is
 * marked unjudged in the artifact rather than filtered here, so the exclusion is a property of the
 * data both rules read rather than a rule remembering to skip something.
 *
 * A grant the ENGINE ships is out too — every server ships administrative accounts by design, and a
 * rule reporting those fires on a database created a minute ago.
 *
 * `FILE` and `PROCESS` are judged on the catalog by SEC.PRIV.GRANT_FILE and SEC.PRIV.GRANT_PROCESS.
 * They stay in the shared list, because the migration-side rule reads it and nothing else reports a
 * migration that grants them, so they are filtered here instead. And the account the audit connected
 * as is not reported for the privileges this package's own setup asks it to hold.
 */
final class AdminPrivilegeGrantRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes
{
    /**
     * What this package's own setup asks its accounts to hold on MySQL: `SHOW_ROUTINE` and `PROCESS`
     * for the audit account, `PROCESS` and `REPLICATION CLIENT` for the preflight one.
     *
     * Not reported on the account the audit connected as, for the reason the server-reach family
     * gives: a tool that reports the privileges its own documentation asks you to grant is a tool
     * nobody trusts twice. Measured before this list existed: the recommended audit account got a
     * `high` finding for `PROCESS, SHOW_ROUTINE`, which `security.min_severity = high` turns into a
     * red build. Any OTHER administrative privilege on that account is still reported.
     *
     * @var list<string>
     */
    public const array AUDIT_SETUP_PRIVILEGES = ['PROCESS', 'REPLICATION CLIENT', 'SHOW_ROUTINE'];

    /**
     * Administrative in the vocabulary and judged on the catalog by rules of their own.
     *
     * The migration-side rule still reads them from the shared list, because no other rule looks at
     * a migration that grants them. On the catalog they are SEC.PRIV.GRANT_FILE and
     * SEC.PRIV.GRANT_PROCESS, and reporting them here as well gave one grant two findings.
     *
     * @var list<string>
     */
    private const array JUDGED_BY_THEIR_OWN_RULE = [FileGrantRule::PRIVILEGE, ProcessGrantRule::PRIVILEGE];

    /**
     * Grants only. The grant reading is refusable on a managed database, which makes "no subject" an
     * ordinary state here — and one a report must not present as a check that ran.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Grant];
    }

    public function id(): string
    {
        return 'SEC.PRIV.GRANT_SERVER_ADMIN';
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Grant) {
            return [];
        }

        if ($object->getBool('judgeable') !== true) {
            return [];
        }

        if ($object->getString('readability') === ReadabilityState::Unreadable->value) {
            return [RuleVerdict::undetermined(
                sprintf('the grant on %s could not be read in full, so whether it carries server-administration rights is unknown', $object->qualifiedName),
                UndeterminedReason::MissingPrivilege,
            )];
        }

        // The engine's own names, kept by the reader precisely so a rule can ask this question. The
        // canonical `privileges` list maps a dynamic privilege onto `other`, which is the same value
        // for all of them — asking there would be asking a question the canonicalization erased.
        $isConnection = $object->getBool('connection_grantee') === true;

        $held = array_values(array_filter(array_map(
            trim(...),
            explode(',', $object->getString('other_privileges') ?? ''),
        ), static fn (string $name): bool => $name !== ''
            && MysqlAdminPrivileges::isAdministrative($name)
            && ! in_array(strtoupper($name), self::JUDGED_BY_THEIR_OWN_RULE, true)
            && (! $isConnection || ! in_array(strtoupper($name), self::AUDIT_SETUP_PRIVILEGES, true))));

        if ($held === []) {
            return [];
        }

        sort($held);

        return [RuleVerdict::flag($this->message(
            $object->getString('grantee') ?? 'the grantee',
            $held,
        ))];
    }

    /** @param  list<string>  $held */
    private function message(string $grantee, array $held): string
    {
        return sprintf(
            '%s holds %s, which administers the SERVER rather than any one database. That reaches beyond '
            .'the data this account was given access to: depending on which of them it is, it can change '
            .'global settings, end other accounts\' sessions, or have the server run code as somebody else '
            .'— none of which a schema grant can express or a schema review would show. Note that %s does '
            .'not have to include SUPER to mean this: MySQL 8.0 deprecated SUPER and split its powers '
            .'across these dynamic privileges, so an account can be an administrator in every practical '
            .'sense while a check for SUPER alone comes back empty. Revoke what the account does not use; '
            .'where it genuinely needs one of these, it is worth a comment beside the GRANT saying which '
            .'and why.',
            $grantee,
            implode(', ', $held),
            $grantee,
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
            'follows the privileges the server records for this account, not the ones it reaches through membership in another role — an account privileged only by inheritance is a separate question the audit answers elsewhere',
            'judges the names the shipped artifact carries. A privilege the engine adds in a later version is not reported until that artifact is refreshed, which is why it is reconciled against a real server rather than maintained by hand',
        ];
    }
}
