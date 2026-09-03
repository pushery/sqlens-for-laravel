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
 * A MySQL account whose user name is EMPTY.
 *
 * `''@'host'` is a real account, and it is not a name nobody uses — it is a name that matches
 * ANYONE. A client connecting from a matching host under a user name the server does not otherwise
 * know is authenticated as this account. So an anonymous account does not merely exist beside the
 * real ones; it silently catches every typo, every stale credential, every probe.
 *
 * ## Why a fresh server never produces one, and why that makes a hit worth reading
 *
 * MySQL stopped shipping anonymous accounts years ago; `mysql_secure_installation` has removed them
 * for longer than that. So this rule is quiet on anything installed this decade, and a finding is
 * almost always an account carried forward through upgrades from a server old enough to have had
 * one — which is exactly the account nobody remembers creating and nobody audits.
 *
 * ## The pair, and the double report it exists to avoid
 *
 * An anonymous account with no password is the worst version of both problems and ONE fact, so it
 * must produce ONE finding. Three rules could speak about it — this pair plus
 * {@see AbstractNoPasswordRule} — and the split is arranged so exactly one does:
 *
 *   - anonymous AND no password → the `critical` rule here, and {@see AbstractNoPasswordRule} stands
 *     down (it checks the same `anonymous` flag);
 *   - anonymous WITH a password → the `high` rule here;
 *   - named account with no password → the no-password family, as before.
 *
 * The alternative — letting both families speak and deduplicating later — was rejected for the
 * reason the reporting layer already taught this package once: results are deduplicated by rule id
 * AND location, so two different ids about one account are two findings, and the reader has to work
 * out that they are the same account. Deciding it at the rule is the only place it can be decided
 * once.
 */
abstract class AbstractAnonymousAccountRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes
{
    /**
     * Accounts only. A run that read no role produced no subject for this family, and the report has to
     * be able to say that rather than let the silence read as "no anonymous account exists".
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

    /** Whether this rule judges the anonymous accounts that ALSO have no password. */
    abstract protected function judgesPasswordlessAccounts(): bool;

    /** The finding, once this rule has established the account is one of its own. */
    abstract protected function message(string $account): string;

    /** @return list<RuleVerdict> */
    final public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Role) {
            return [];
        }

        if ($object->getBool('system') === true) {
            return [];
        }

        if ($object->getString('readability') === ReadabilityState::Unreadable->value) {
            return [RuleVerdict::undetermined(
                sprintf('the account record for %s could not be read, so whether it is anonymous is unknown', $object->qualifiedName),
                UndeterminedReason::MissingPrivilege,
            )];
        }

        if ($object->getBool('anonymous') !== true) {
            return [];
        }

        $hash = PasswordHashType::tryFrom($object->getString('hash_type') ?? '');

        // A credential state nobody could read cannot decide which of the pair speaks, and guessing
        // would put the account in the milder half exactly when the reading was worst. The account is
        // reported as undetermined rather than assigned — the anonymity itself is certain, but the
        // finding this package would give is not, and half a finding is the thing it refuses.
        if ($hash === null || ! $hash->isKnown()) {
            return [RuleVerdict::undetermined(
                sprintf(
                    '%s is an anonymous account — an empty user name that authenticates anybody connecting from a '
                    .'matching host — but its credential state was withheld from this reading, so whether it also '
                    .'has no password is unknown. Both cases are reportable and they differ in weight, so this is '
                    .'left open rather than assigned to the milder one.',
                    $object->qualifiedName,
                ),
                UndeterminedReason::MissingPrivilege,
            )];
        }

        if (($hash === PasswordHashType::None) !== $this->judgesPasswordlessAccounts()) {
            return [];
        }

        return [RuleVerdict::flag($this->message($object->qualifiedName))];
    }
}
