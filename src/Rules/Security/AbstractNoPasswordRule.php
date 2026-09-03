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
 * A MySQL account that can log in and has no password at all.
 *
 * The reader already answers this: an account on a password plugin whose `authentication_string` is
 * empty becomes {@see PasswordHashType::None}. Anyone who can reach the port and knows the account
 * name is in — no cracking, no capture, no interception. It is the shortest path into a database
 * there is.
 *
 * ## Why this rule asks which ENGINE it is looking at, when its sibling refuses to
 *
 * {@see AbstractDeprecatedPasswordHashRule} makes a point of carrying no driver check: the reader
 * maps PostgreSQL's `md5…` and MySQL's `mysql_native_password` onto one value, so the FACT is
 * engine-neutral and a rule that asked would be asking about spelling.
 *
 * `None` is spelled the same way by both readers and does not mean the same thing, which is the
 * opposite situation. PostgreSQL's mapping produces it from `rolpassword IS NULL` — and on
 * PostgreSQL that is ordinary, frequently correct, and says nothing about who can log in. A role
 * that exists to own objects has no password by design; a role that authenticates by peer, ident or
 * GSSAPI has none because the credential is not a password. Whether anybody can connect as it is
 * decided in `pg_hba.conf`, a separate reading with its own rules — `SEC.AUTH.HBA_TRUST` is where an
 * open door on PostgreSQL actually shows up.
 *
 * So a rule that reported `None` on both engines would fire on most PostgreSQL databases for a state
 * their operators chose on purpose, and it would be switched off before it ever caught the MySQL
 * case it exists for. The driver check is what keeps it worth having.
 *
 * ## The false positive this rule is really about
 *
 * An empty credential field is normal for an account whose credential lives somewhere else —
 * `auth_socket`, PAM, LDAP. The reader draws that line already and calls those accounts
 * {@see PasswordHashType::External}, from the PLUGIN rather than from the emptiness of the field, so
 * this rule never sees them. That is the whole reason it reads the enum instead of the raw column:
 * a check written against the column would report every socket-authenticated account on every
 * server, which is how a security rule earns a permanent `--ignore`.
 *
 * ## Why the locked case is a second rule and not a second severity
 *
 * Same as the sibling family, and for the same reason: severity in this package is metadata on the
 * RULE, so "the same finding, less urgent" cannot be said by one rule reading its own subject twice.
 * A locked account with no password cannot be used today, and unlocking it is one statement — after
 * which it is wide open again. Reporting it at `critical` would bury the account that is open right
 * now; not reporting it would make locking look like a fix.
 */
abstract class AbstractNoPasswordRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes
{
    /**
     * Accounts only — whether a credential exists is an attribute of a role.
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
    abstract protected function message(string $account): string;

    /** @return list<RuleVerdict> */
    final public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Role) {
            return [];
        }

        // PostgreSQL, where the same value is ordinary — see the class docblock. Checked before
        // anything else so the reasoning below is only ever read in the engine it applies to.
        if ($object->context()->driver !== 'mysql') {
            return [];
        }

        // The engine's own accounts. On a stock MySQL 8.4 `mysql.sys`, `mysql.session` and
        // `mysql.infoschema` all carry `caching_sha2_password` with a real credential, so this
        // exclusion is not what keeps the rule quiet on a fresh server. It is here because a system
        // account is not something a project can change, and a finding nobody can act on is noise.
        if ($object->getBool('system') === true) {
            return [];
        }

        if ($object->getString('readability') === ReadabilityState::Unreadable->value) {
            return [RuleVerdict::undetermined(
                sprintf('the account record for %s could not be read, so whether it has a password is unknown', $object->qualifiedName),
                UndeterminedReason::MissingPrivilege,
            )];
        }

        $hash = PasswordHashType::tryFrom($object->getString('hash_type') ?? '');

        // `Withheld` is the reader's name for "the catalog would not show me", and it is a case
        // rather than a null precisely so a rule cannot fold it into `None`. That substitution is
        // the one that matters here more than anywhere else in the package: it would turn "nobody
        // could look" into "this account has no password", which is a locked door reported as an
        // open one — and somebody would go and set a password on an account that already had one.
        if ($hash === null || ! $hash->isKnown()) {
            return [RuleVerdict::undetermined(
                sprintf('the credential state of %s was withheld from this reading, so whether it has a password is unknown', $object->qualifiedName),
                UndeterminedReason::MissingPrivilege,
            )];
        }

        if ($hash !== PasswordHashType::None) {
            return [];
        }

        // An ANONYMOUS account with no password belongs to the anonymous family, which reports both
        // halves in one finding at `critical`. Speaking here as well would produce two ids about one
        // account, and the reporting layer deduplicates by rule id AND location — so both survive,
        // and the reader is left to work out that they are the same account.
        //
        // The stand-down lives here rather than there because this is the rule that would be the
        // SECOND voice: the anonymous finding says strictly more (no name AND no password), so the
        // narrower statement is the one that yields.
        if ($object->getBool('anonymous') === true) {
            return [];
        }

        // `usable` is false when the account is locked or its password has expired. The two rules in
        // this family split on it, so exactly one of them ever speaks about a given account.
        if ($object->getBool('usable') !== $this->judgesUsableAccounts()) {
            return [];
        }

        return [RuleVerdict::flag($this->message($object->qualifiedName))];
    }
}
