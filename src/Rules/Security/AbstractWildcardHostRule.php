<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Pushery\SQLens\Catalog\Objects\ReadabilityState;
use Pushery\SQLens\Catalog\Objects\RoleObject;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * An account that may connect from ANY host.
 *
 * A MySQL account is a name AND a host pattern, and the host half is a real access control: `%`
 * matches every address there is. On its own that is a `medium` finding rather than an alarm —
 * plenty of deployments have a legitimate reason for it, and a rule that shouted would be switched
 * off by exactly the people who have the most accounts.
 *
 * What sharpens it is what the account can DO once it arrives, which is why this is a pair.
 *
 * ## No driver check here, unlike its no-password neighbor
 *
 * {@see AbstractNoPasswordRule} has to ask which engine it is looking at, because both readers
 * produce the same value from facts that do not mean the same thing. This family does not, and for
 * a better reason than convention: a host pattern is a MySQL concept, PostgreSQL roles carry no
 * host at all, and {@see RoleObject::hasWildcardHost()} answers
 * false for every one of them. The rule is MySQL-only by the FACT rather than by a check, which is
 * the shape the rest of this family prefers — the engine cannot drift out from under it.
 *
 * ## Why the escalation is a second id, and where its input comes from
 *
 * Severity is metadata on the RULE, so "the same finding, sharper" has to be a second id. That
 * constraint fits what is actually being said: an open host on an unprivileged account is a matter
 * of tightening a pattern, and an open host on an account that can do anything is an incident
 * waiting for someone to guess a password.
 *
 * The privilege half is read from the subject's own `privileged` flag rather than re-derived from
 * grants, and that is worth stating because it looks like a shortcut and is not. Measured on a real
 * MySQL 8.4: an account holding nothing but `GRANT ALL PRIVILEGES ON *.*` is read back carrying
 * `superuser`, `create_role`, `create_database` and `replication` — the reader turns MySQL's
 * far-reaching grants into role attributes, from the SAME `mysql.user` reading the account itself
 * comes from. So the escalation and the account are one reading, and one readability question,
 * rather than two that could disagree.
 *
 * That is also why an unreadable record is `undetermined` for BOTH rules rather than quietly
 * landing on the milder one. Choosing `medium` because the privilege half could not be read would
 * be a downgrade nobody asked for and nobody could see.
 */
abstract class AbstractWildcardHostRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes
{
    /**
     * Accounts only — the host part this family judges belongs to a role's identity.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Role];
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

    /** Whether this rule judges the accounts that also hold far-reaching privileges. */
    abstract protected function judgesPrivilegedAccounts(): bool;

    /** The finding, once this rule has established the account is one of its own. */
    abstract protected function message(string $account): string;

    /** @return list<RuleVerdict> */
    final public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Role) {
            return [];
        }

        // The engine's own accounts. All three ship on `localhost`, so they would not reach the
        // wildcard branch anyway — the exclusion is here because a system account is not something
        // a project can change, and it keeps the rule honest if a future release moves one.
        if ($object->getBool('system') === true) {
            return [];
        }

        if ($object->getString('readability') === ReadabilityState::Unreadable->value) {
            return [RuleVerdict::undetermined(
                sprintf('the account record for %s could not be read, so which hosts it accepts is unknown', $object->qualifiedName),
                UndeterminedReason::MissingPrivilege,
            )];
        }

        if ($object->getBool('wildcard_host') !== true) {
            return [];
        }

        // The split. Exactly one of the two speaks about any given account.
        if ($object->getBool('privileged') !== $this->judgesPrivilegedAccounts()) {
            return [];
        }

        return [RuleVerdict::flag($this->message($object->qualifiedName))];
    }
}
