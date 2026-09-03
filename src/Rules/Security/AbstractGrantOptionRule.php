<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Pushery\SQLens\Catalog\Objects\ReadabilityState;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A grant an account may HAND ON — `WITH GRANT OPTION`.
 *
 * Every other grant rule in this package asks what an account can do. This one asks what it can give
 * away, and that is a different kind of fact: it makes every other restriction on the server
 * voluntary. An account that may re-grant what it holds can create a second account holding the
 * same, and the second one carries no note saying where it came from — so a privilege audit run
 * tomorrow sees a plain account, and the path that made it is invisible.
 *
 * ## Engine-neutral, and that is measured rather than assumed
 *
 * Unlike the wildcard-host family, which judges a fact PostgreSQL does not have, both readers
 * already produce this one: MySQL from `GRANT OPTION` in the grant tables and from its
 * `SHOW GRANTS` fallback text, PostgreSQL from `aclexplode().is_grantable`. It is the same decision
 * with two spellings, so the rule carries no driver check and neither engine gets a second opinion.
 *
 * ## Why the escalation reads the grant and not the account
 *
 * The ticket asks for `high` when the same account also holds far-reaching privileges. The obvious
 * reading is to look up the account's other grants — and that would be two readings that can
 * disagree, plus a readability question the finding would have to carry.
 *
 * It is not needed. A grant that is BOTH re-grantable and broad is one subject: `privileges` and
 * `grantable` sit on the same row of the same reading. So the split is "how much does THIS grant
 * hand on", which is answerable from what the rule already has, and which is also the sharper
 * statement — an account that may re-grant `SELECT` on one table is a different problem from one
 * that may re-grant the ability to change the schema.
 *
 * ## What is deliberately not reported
 *
 * A grant the ENGINE ships. `isJudgeable()` is false for anything that is not a project decision,
 * and a rule reporting those would fire on a database created a minute ago — the same reason the
 * rest of the grant family checks it.
 */
abstract class AbstractGrantOptionRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes
{
    /**
     * Grants only. On a run where the grant reading was refused there is nothing to judge, and a report
     * that implied otherwise would state an absence about a surface it never saw.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Grant];
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

    /** Whether this rule judges the grants that also hand on STRUCTURAL power. */
    abstract protected function judgesStructuralGrants(): bool;

    /** The finding, once this rule has established the grant is one of its own. */
    abstract protected function message(string $grantee, string $target): string;

    /** @return list<RuleVerdict> */
    final public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Grant) {
            return [];
        }

        // What the engine ships is not a decision anybody made, and a rule reporting it fires on
        // every fresh database.
        if ($object->getBool('judgeable') !== true) {
            return [];
        }

        if ($object->getString('readability') === ReadabilityState::Unreadable->value) {
            return [RuleVerdict::undetermined(
                sprintf('the grant on %s could not be read in full, so whether it can be handed on is unknown', $object->qualifiedName),
                UndeterminedReason::MissingPrivilege,
            )];
        }

        if ($object->getBool('grantable') !== true) {
            return [];
        }

        // The split. `structural` is the reading's own word for "this hands out the power to change
        // the schema rather than the data in it" — read rather than re-derived from the privilege
        // list, so this rule and the ones that already use it cannot disagree about one grant.
        if ($object->getBool('structural') !== $this->judgesStructuralGrants()) {
            return [];
        }

        return [RuleVerdict::flag($this->message(
            $object->getString('grantee') ?? 'the grantee',
            $object->getString('target') ?? $object->qualifiedName,
        ))];
    }
}
