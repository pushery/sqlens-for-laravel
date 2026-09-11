<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Pushery\SQLens\Catalog\Objects\ReadabilityState;
use Pushery\SQLens\Catalog\Objects\RoleAttribute;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Contracts\JudgesTheServerItRunsOn;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The shape every "this account holds a dangerous role attribute" rule has.
 *
 * Three of them exist and they differ in exactly two things: which attribute, and what it costs. The
 * rest is identical and belongs in one place — not out of tidiness, but because the parts that are
 * easy to get subtly wrong are the same parts each time:
 *
 * - **Held vs. reachable.** PostgreSQL does not inherit role ATTRIBUTES through membership. A member
 *   of a superuser role is not a superuser; it can `SET ROLE` and then be one. Both are findings and
 *   they are not the same finding, so the base reports them separately and a rule that only knew the
 *   first would be silent on the more common shape.
 * - **The path.** A finding that says "this account reaches superuser" and stops is not resolvable:
 *   somebody has to know which grant to revoke, and on a three-step chain that is two grants they
 *   cannot see from the endpoint. The base prints it.
 * - **The engine's own accounts.** `pg_monitor` and its siblings hold attributes by design. Reporting
 *   them would fire on every fresh server, which is how a rule gets switched off.
 * - **An unread account.** "This role has no dangerous attribute" and "we could not read its
 *   attributes" are the same sentence to a reader who cannot tell them apart, and only one is good
 *   news.
 */
abstract class AbstractRoleAttributeRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes, JudgesTheServerItRunsOn
{
    /**
     * Accounts only, by definition: the family is named for the attribute it reads off one.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Role];
    }

    /**
     * The connecting role's attributes are a property of the SERVER, not of the schema.
     *
     * `connection_role` above already narrows this family to the one account the audit authenticated
     * as, and on a container that account is whatever the service block named — `POSTGRES_USER:
     * postgres` in every Woodpecker lane of this fleet, which is a superuser by construction. The
     * same attribute on a role somebody deploys with is one of the most serious things here.
     */
    public function serverSubjectJudged(): string
    {
        return 'the attributes of the role this audit connects as';
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /** The attribute this rule is about. */
    abstract protected function attribute(): RoleAttribute;

    /** What holding it means, as the finding's opening sentence. */
    abstract protected function heldMessage(string $role): string;

    /** What being able to assume it means — the `SET ROLE` case, with the path that leads there. */
    abstract protected function reachableMessage(string $role, string $path): string;

    /**
     * Whether another rule already reports this account, so this one stays quiet.
     *
     * Default: nothing supersedes. `SUPERUSER` overrides it for the two lesser attributes, because an
     * account that is already superuser holds every one of them by definition and three findings
     * about one account would bury the one that matters under two that follow from it.
     */
    protected function supersededBy(SchemaObject $object): bool
    {
        return false;
    }

    /** @return list<RuleVerdict> */
    final public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Role) {
            return [];
        }

        // The engine's own accounts hold these attributes by design.
        if ($object->getBool('system') === true) {
            return [];
        }

        // …and only the account the audit connected as is judged. Every PostgreSQL server ships a
        // `postgres` superuser and every MySQL server a `root`; a rule reporting all of them would
        // report one on a database created thirty seconds ago, which is how a rule gets switched off.
        // What a project can act on — and what the finding can name a fix for — is its own role.
        if ($object->getBool('connection_role') !== true) {
            return [];
        }

        if ($object->getString('readability') === ReadabilityState::Unreadable->value) {
            return [RuleVerdict::undetermined(
                sprintf('the attributes of %s could not be read, so whether it holds %s is unknown', $object->qualifiedName, $this->attribute()->value),
                UndeterminedReason::MissingPrivilege,
            )];
        }

        // A partial reading that is missing exactly the field this rule judges. Reported rather than
        // passed over: the account may well hold the attribute, and nothing here can tell.
        if (str_contains($object->getString('withheld_fields') ?? '', 'attributes')) {
            return [RuleVerdict::undetermined(
                sprintf('%s was read without its attributes, so whether it holds %s is unknown', $object->qualifiedName, $this->attribute()->value),
                UndeterminedReason::MissingPrivilege,
            )];
        }

        if ($this->supersededBy($object)) {
            return [];
        }

        if ($this->holds($object, 'attributes')) {
            return [RuleVerdict::flag($this->heldMessage($object->qualifiedName))];
        }

        if ($this->holds($object, 'reachable_attributes')) {
            return [RuleVerdict::flag($this->reachableMessage($object->qualifiedName, $this->pathIn($object)))];
        }

        return [];
    }

    /** Whether the named attribute set carries this rule's attribute. */
    protected function holds(SchemaObject $object, string $field): bool
    {
        $attributes = explode(',', $object->getString($field) ?? '');

        return in_array($this->attribute()->value, $attributes, true);
    }

    /**
     * The membership chain that leads to the attribute, or a stated absence.
     *
     * The absence is spelled out rather than left blank: a path this reading could not establish is
     * a fact about the reading, and an empty string in the middle of a sentence reads like a bug.
     */
    private function pathIn(SchemaObject $object): string
    {
        foreach (explode(';', $object->getString('reachable_paths') ?? '') as $entry) {
            if (str_contains($entry, '=')) {
                return explode('=', $entry, 2)[1];
            }
        }

        return 'the membership chain could not be established';
    }
}
