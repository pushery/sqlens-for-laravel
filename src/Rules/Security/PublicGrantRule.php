<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Catalog\Objects\ReadabilityState;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleIdFormat;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A privilege granted to `PUBLIC` — which means to every role that exists and every role that ever
 * will.
 *
 * PUBLIC is not a group somebody joins. It is the implicit membership of every role in the database,
 * including the one created next month for a contractor and the one an extension installs. A grant to
 * it cannot be audited by looking at who has access, because the answer is "everyone", and it survives
 * every review of the role list because it appears in none of them.
 *
 * ## The false positive this rule lives or dies by
 *
 * Every PostgreSQL database ships with grants to PUBLIC: `CONNECT` and `TEMPORARY` on the database
 * itself, `EXECUTE` on a hundred-odd system functions, and — before version 15 — `CREATE` on the
 * `public` schema. A rule that reported those would fire on a freshly created, entirely untouched
 * database, and a security rule that cries on `CREATE DATABASE` is switched off in its first week and
 * is worth less than no rule at all.
 *
 * So it judges only what the reader marked as a PROJECT decision. The reader reads that from
 * `pg_init_privs` — PostgreSQL's own record of the ACL an object had when initdb finished or when the
 * extension that owns it was installed — rather than from a list of names this rule would have to keep
 * in step with the server. That is also what settles the version question the ticket raises: the
 * `public` schema's `CREATE` grant was withdrawn in PostgreSQL 15, and on any server this rule runs
 * against, whatever that server shipped is exactly what its own catalog says it shipped. Nothing here
 * needs to know which version changed what.
 *
 * ## What it does not claim
 *
 * That the grant is wrong. `EXECUTE` to PUBLIC on a project's own helper function is often deliberate,
 * and `USAGE` on a schema is how many applications are laid out. The finding says a privilege reaches
 * every role, names which, and leaves the decision where it belongs — which is why it is `medium`
 * rather than `high`, and why the message asks a question instead of issuing an instruction.
 */
final class PublicGrantRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes
{
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

    /**
     * `SEC.PRIV.GRANT_PUBLIC`, and not the `SEC.PG.GRANT.PUBLIC` the plan's ticket writes.
     *
     * The scheme was fixed before the first rule existed and is machine-enforced
     * ({@see RuleIdFormat}): `<AREA>.L<n>.<NAME>`. `SEC` is the area for the security family, which is
     * also why this rule lives in Core rather than under a driver — the PostgreSQL pack's own guard
     * refuses a security-category rule in so many words, because a severity-gated rule filed under an
     * engine's safety pack would bypass the level gate that pack is measured by.
     *
     * Engine-neutral by construction rather than by ambition: the rule judges a GRANT subject, and
     * MySQL has no PUBLIC pseudo-role, so `to_public` is never true there. It has nothing to say on
     * that engine and says nothing, without a driver check anywhere in it.
     */
    public function id(): string
    {
        return 'SEC.PRIV.GRANT_PUBLIC';
    }

    /**
     * Level 0: this is not a matter of appetite for strictness.
     *
     * A security finding is measured against the RISK axis, not the level one, so its level says only
     * "no run excludes it". A project that does not want to hear about grants raises
     * `security.min_severity` above `medium` — one dial, stated once, rather than a level that would
     * silently take the whole security category with it.
     */
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
        if ($object->type !== SchemaObjectType::Grant || $object->getBool('to_public') !== true) {
            return [];
        }

        // A reading that could not see the ACL says so, and this rule says so with it. "No PUBLIC
        // grants found" and "the grants could not be read" are the same sentence to a reader who
        // cannot tell them apart, and only one of them is good news.
        if ($object->getString('readability') === ReadabilityState::Unreadable->value) {
            return [RuleVerdict::undetermined(
                sprintf('the grants on %s could not be read, so whether PUBLIC holds any is unknown', $object->getString('target') ?? '?'),
                UndeterminedReason::MissingPrivilege,
            )];
        }

        // What PostgreSQL itself put there is not a finding. This is the whole rule.
        if ($object->getBool('judgeable') !== true) {
            return [];
        }

        return [RuleVerdict::flag($this->message($object))];
    }

    private function message(SchemaObject $object): string
    {
        $privileges = $object->getString('privileges') ?? '';

        return sprintf(
            'PUBLIC holds %s on the %s %s. PUBLIC is not a group somebody joins — it is the implicit '
            .'membership of every role in this database, including every role created from now on, so '
            .'this privilege cannot be reviewed by looking at who has access and it appears in no role '
            .'listing. PostgreSQL\'s own default grants are excluded here, so this one was granted by '
            .'somebody: check whether it still needs to be, and REVOKE %s ON %s FROM PUBLIC if not.',
            str_replace(',', ', ', $privileges),
            $object->getString('target_type') ?? 'object',
            $object->getString('target') ?? '?',
            strtoupper(str_replace(',', ', ', $privileges)),
            $object->getString('target') ?? '?',
        );
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'PUBLIC reaches roles that do not exist yet, so this finding is about the future as much as the present — and how much it matters depends on who will be able to create a role, which is a separate rule\'s subject',
            'cannot tell a deliberate PUBLIC grant from an inherited one: an extension\'s install script grants to PUBLIC by design, and the catalog does not record who granted what',
        ];
    }
}
