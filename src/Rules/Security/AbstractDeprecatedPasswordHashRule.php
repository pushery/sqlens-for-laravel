<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Pushery\SQLens\Catalog\Objects\PasswordHashType;
use Pushery\SQLens\Catalog\Objects\ReadabilityState;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * An account whose stored password uses a hash both engines have deprecated.
 *
 * PostgreSQL calls it `md5`; MySQL calls it `mysql_native_password`. The reader already maps both
 * onto {@see PasswordHashType::Md5}, so this family judges the FACT rather than either engine's
 * spelling of it — no driver check appears in any of these rules.
 *
 * ## Why it is worth reporting, on both engines, for different reasons
 *
 * On PostgreSQL the md5 verifier is salted with the ROLE NAME and nothing else. A captured digest is
 * crackable offline and usable as the password itself against any server where that role exists, so
 * two databases sharing a role name share the exposure. PostgreSQL 18 warns when one is created.
 *
 * On MySQL `mysql_native_password` is off by default in 8.4 and **removed in 9.0**. So the account
 * carries two separate problems that happen to arrive together: a weaker verifier now, and an
 * account that stops being able to log in at the next major. Neither is visible from the connection
 * string, and the second one is the kind of thing that is discovered during an upgrade window.
 *
 * ## Why every non-system account, and not only the one the audit connected as
 *
 * The sibling family {@see AbstractRoleAttributeRule} judges only the connecting role, because every
 * server ships a superuser by design and reporting all of them would fire on a database created
 * thirty seconds ago.
 *
 * That argument does not transfer, and it was measured rather than assumed: on a stock MySQL 8.4 all
 * six accounts — including the three `mysql.*` system ones — are `caching_sha2_password`. A
 * deprecated hash is nobody's default, so this rule reports nothing on a fresh server, and each
 * account it does report is one somebody has to migrate before the next major.
 *
 * ## Why the locked case is a second rule and not a second severity
 *
 * Severity in this package is metadata on the RULE, so "the same finding but less severe" is not
 * expressible — and should not be. A locked account with a deprecated hash is a different sentence:
 * it cannot log in today, and unlocking it is one statement. Reporting it at the same weight as a
 * live account would bury the live one; not reporting it at all would let an account come back
 * carrying the problem it was locked with.
 */
abstract class AbstractDeprecatedPasswordHashRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes
{
    /**
     * Accounts only — the stored verifier is an attribute of a role, and nothing else carries one.
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

    /** Whether this rule judges the usable accounts or the locked ones. */
    abstract protected function judgesUsableAccounts(): bool;

    /** The finding, once this rule has established the account is one of its own. */
    abstract protected function message(string $account, string $driver): string;

    /** @return list<RuleVerdict> */
    final public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Role) {
            return [];
        }

        // The engine's own accounts. Measured as `caching_sha2_password` on a stock 8.4, so this
        // exclusion is not what keeps the rule quiet there — it is here because a system account is
        // not something a project can migrate, and a finding it cannot act on is noise either way.
        if ($object->getBool('system') === true) {
            return [];
        }

        if ($object->getString('readability') === ReadabilityState::Unreadable->value) {
            return [RuleVerdict::undetermined(
                sprintf('the account record for %s could not be read, so which verifier its password is stored under is unknown', $object->qualifiedName),
                UndeterminedReason::MissingPrivilege,
            )];
        }

        $hash = PasswordHashType::tryFrom($object->getString('hash_type') ?? '');

        // The reader has its own name for "I could not see it", and it is a CASE rather than a null —
        // exactly so that a rule cannot coalesce it into "no password" and read a gap as a fact. Both
        // predicates below are the enum's own, and both were written before any rule called them: the
        // docblock on `isDeprecated()` says "rules should flag", and until now none did.
        if ($hash === null || ! $hash->isKnown()) {
            return [RuleVerdict::undetermined(
                sprintf('the password verifier of %s was withheld from this reading, so whether it is a deprecated one is unknown', $object->qualifiedName),
                UndeterminedReason::MissingPrivilege,
            )];
        }

        if (! $hash->isDeprecated()) {
            return [];
        }

        // `usable` is false when the account is locked or its password has expired. The two rules in
        // this family split on it, so exactly one of them speaks about any given account.
        if ($object->getBool('usable') !== $this->judgesUsableAccounts()) {
            return [];
        }

        return [RuleVerdict::flag($this->message($object->qualifiedName, $object->context()->driver))];
    }
}
