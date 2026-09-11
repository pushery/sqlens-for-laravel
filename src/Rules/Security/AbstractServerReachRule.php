<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Contracts\JudgesTheServerItRunsOn;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The shape shared by the two privileges that reach PAST the database into the machine running it.
 *
 * `FILE` reads and writes files as the server process. `PROCESS` shows every other session's current
 * statement. Neither touches a row, and neither is an administrative power over the server — which is
 * why they sit here rather than under the administrative-privilege rule: an account can hold either
 * one while being unable to change a single server setting.
 *
 * ## Why one base class and two ids
 *
 * Severity is metadata on a rule, so two severities need two rules. What they share is the SHAPE of
 * the question — a named global privilege, gated on the same three conditions — and sharing it here
 * means a change to the gate cannot apply to one and not the other.
 *
 * ## The three gates, and why each one is a gate
 *
 * A grant the ENGINE ships is never judged: MySQL's `mysql.session` holds server privileges out of
 * the box, and a rule reporting it would open on a fresh install with a finding nobody caused.
 *
 * The privilege is looked for among the ENGINE-NAMED ones. `FILE` and `PROCESS` have no PostgreSQL
 * equivalent, so canonicalization maps both to the unmapped case — asking the canonical list would
 * ask a question the mapping has already erased. This is also what makes the pair silent on
 * PostgreSQL without a driver check: that engine simply never produces these names.
 *
 * And the account SQLens itself connected as is excluded, which is the sharpest of the three. This
 * package's own setup guidance asks for a read-only audit account, and a monitoring account needs
 * `PROCESS` to do its job. A tool that reports the very privileges its own documentation asks you to
 * grant is a tool nobody trusts twice — so the exclusion is part of the rule rather than a note in
 * the docs.
 */
abstract class AbstractServerReachRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes, JudgesTheServerItRunsOn
{
    /**
     * Grants only — the family judges how far a privilege reaches, and a privilege is held by a grant.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Grant];
    }

    /**
     * The name says it: a privilege that reaches past the DATABASE to the server is a fact about the
     * server, whoever holds it.
     *
     * ⚠️ And this is the family that shows why the declaration belongs to the rule rather than to a
     * prefix list. Its ids sit under `SEC.PRIV.*` alongside {@see GrantToPublicRule}, which judges a
     * grant on a table this project's own migrations created — as real inside a container as on any
     * host, and not withheld here. Same prefix, opposite answer.
     */
    public function serverSubjectJudged(): string
    {
        return 'a privilege that reaches the whole server rather than this database';
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

        // The audit's own account. See the class docblock — this is the gate that keeps the package
        // from complaining about the setup it documents.
        if ($object->getBool('connection_grantee') === true) {
            return [];
        }

        if (! $this->holdsPrivilege($object)) {
            return [];
        }

        return [RuleVerdict::flag($this->message($object))];
    }

    /**
     * Whether the grant carries this rule's privilege, under the engine's own name.
     *
     * `other_privileges` rather than `privileges`: neither `FILE` nor `PROCESS` has a case in the
     * canonical vocabulary, so both arrive there keeping their names — which is exactly the design,
     * and exactly what a rule about one of them has to read.
     */
    private function holdsPrivilege(SchemaObject $object): bool
    {
        $held = explode(',', $object->getString('other_privileges') ?? '');

        return in_array($this->privilege(), array_map(trim(...), $held), true);
    }

    /** The MySQL privilege name this rule reports, upper-cased as the reading carries it. */
    abstract protected function privilege(): string;

    abstract protected function message(SchemaObject $object): string;

    /** The account, as the reading spells it — `'name'@'host'` on MySQL. */
    protected function grantee(SchemaObject $object): string
    {
        return $object->getString('grantee') ?? '?';
    }
}
