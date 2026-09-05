<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L6;

use Override;
use Pushery\SQLens\Catalog\CrossFactState;
use Pushery\SQLens\Catalog\SettingCrossFacts;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Contracts\ProvidesSchemaObjectRemediation;
use Pushery\SQLens\Drivers\Mysql\Catalog\MysqlSettingCrossFactCollector;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\OffersAConsideredNone;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A MySQL server whose `lower_case_table_names` is a risk for THIS project.
 *
 * ## Why this rule cannot judge against the matrix, and does not try
 *
 * `lower_case_table_names` is the one shipped matrix entry deliberately marked unjudged: `0` is
 * right on Linux, `2` is what a macOS install gives you, and there is no value that is correct
 * everywhere. A rule asserting one would be wrong on half of all deployments.
 *
 * So this is a catalog rule rather than a matrix-expectation rule, and it judges against two things
 * the package CAN stand behind:
 *
 * 1. **A project statement.** `sqlens.audit.expect.lower_case_table_names` says what this project
 *    wants its servers to be. Unset — the shipped default — this trigger says nothing at all, which
 *    is the right amount of noise for a project that has never cared.
 * 2. **The catalog itself.** On `0` the server is case-SENSITIVE, so a schema already holding a
 *    table named `Orders` is one where a migration writing `orders` will not find it. That is
 *    objectively provable without anybody stating a preference, so it fires either way.
 *
 * ## The remediation is naming, not a switch
 *
 * The value is fixed when the server is initialized and cannot be changed afterwards: moving it
 * means a new server and a dump/reload. A rule proposing `SET GLOBAL` here would be proposing
 * something MySQL refuses. So the finding proposes CONSISTENT NAMING — the thing a project can
 * actually do this afternoon — and says the switch is not available.
 */
final class LowerCaseTableNamesRiskRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes, ProvidesSchemaObjectRemediation
{
    use OffersAConsideredNone;

    /**
     * Why there is no standard sequence here.
     *
     * The rule's own docblock settles this one: the value *"is fixed when the server is initialized and
     * cannot be changed afterwards"*. It shares the answer with every initdb-scoped server setting,
     * and the shared key is the point — one fact, one sentence, however many rules meet it.
     *
     * The trait decides WHEN this is attached — only where this rule itself flagged — so the rule
     * only has to say what it concluded.
     */
    #[Override]
    protected function noSequenceReasonKey(): string
    {
        return 'sqlens::messages.remediation.no_safe_sequence.server_setting_initdb';
    }

    /**
     * Server variables only. The rule narrows twice — this type, then one variable name — so a run
     * whose reading never named that variable never asked this question at all.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Setting];
    }

    /** @var int|null what this project stated it wants, or null when it stated nothing */
    private ?int $expected = null;

    /** The project's stated target, threaded from `sqlens.audit.expect.lower_case_table_names`. */
    public function expecting(?int $value): self
    {
        $clone = clone $this;
        $clone->expected = $value;

        return $clone;
    }

    public function id(): string
    {
        return 'MY.L6.LOWER_CASE_TABLE_NAMES_RISK';
    }

    public function level(): Level
    {
        return Level::TypeIdiom;
    }

    public function category(): Category
    {
        return Category::Safety;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Setting || $object->qualifiedName !== 'lower_case_table_names') {
            return [];
        }

        $value = $object->getString('server_value');

        if ($value === null) {
            return [RuleVerdict::undetermined(
                'lower_case_table_names could not be read from this server, so neither the project\'s '
                .'expectation nor the names already in the catalog could be checked against it.',
                UndeterminedReason::MissingPrivilege,
            )];
        }

        $verdicts = [];

        if ($this->expected !== null && (int) $value !== $this->expected) {
            $verdicts[] = RuleVerdict::flag(sprintf(
                'this server runs lower_case_table_names = %s while the project states it expects %d '.
                '(sqlens.audit.expect.lower_case_table_names). That is the classic development-'.
                'against-production split: a migration with mixed-case names passes on one and fails '.
                'on the other, and nothing about the migration says which. The value is fixed when a '.
                'server is initialized and cannot be changed afterwards — moving it means a new '.
                'server and a dump/reload — so the fix is to make the two environments agree, either '.
                'by rebuilding this one or by correcting the expectation.',
                $value,
                $this->expected,
            ));
        }

        return [...$verdicts, ...$this->caseSensitiveWithMixedNames($object, $value)];
    }

    /**
     * The trigger that needs no project statement: a case-sensitive server already holding names
     * that depend on their case.
     *
     * @return list<RuleVerdict>
     */
    private function caseSensitiveWithMixedNames(SchemaObject $object, string $value): array
    {
        if ((int) $value !== 0) {
            return [];
        }

        // Read through the collaborator rather than re-derived: this rule is NOT a setting rule —
        // it judges against a project statement and the catalog, so it does not inherit
        // AbstractServerSettingRule's accessor — and a second copy of the key convention here is
        // exactly the drift the collaborator exists to prevent.
        $state = SettingCrossFacts::stateOn($object, MysqlSettingCrossFactCollector::MIXED_CASE_TABLES);

        if ($state === CrossFactState::Unavailable) {
            return [RuleVerdict::undetermined(
                'this server is case-sensitive (lower_case_table_names = 0), and the table names in '
                .'the schema could not be read — so whether any of them depends on its case is '
                .'unknown rather than fine.',
                UndeterminedReason::CatalogReadFailed,
            )];
        }

        $mixed = (string) $object->getString(MysqlSettingCrossFactCollector::MIXED_CASE_TABLES);

        if ($mixed === '') {
            return [];
        }

        return [RuleVerdict::flag(sprintf(
            'this server is case-sensitive (lower_case_table_names = 0) and the schema already holds '.
            'table names that are not all lower case: %s. A migration or query writing the same name '.
            'in a different case will not find them here, while it would on a server initialized with '.
            '1 or 2 — which is exactly how a suite that is green locally fails in production. The '.
            'setting cannot be changed on an existing server, so the fix is consistent lower-case '.
            'naming rather than a switch.',
            $mixed,
        ))];
    }
}
