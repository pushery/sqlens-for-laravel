<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L8;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Contracts\JudgesMigrationStatements;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Convention\NamingConvention;
use Pushery\SQLens\Rules\Convention\SnakeCaseIdentifiers;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * An identifier that does not survive MySQL unquoted.
 *
 * ## On MySQL the answer is a SERVER setting, so it differs by machine
 *
 * `lower_case_table_names` is 2 on a developer's Mac and 0 on a Linux server. The same migration
 * therefore makes one table on the laptop and a different one in production, and the failure
 * arrives later as "table doesn't exist" — far from the deploy that caused it.
 *
 * ## One judgment, two subject sources
 *
 * The same question is asked of a migration statement before it runs and of the catalog after it
 * did, because both answers are useful and neither replaces the other: lint catches the name while
 * it is still a diff, audit catches the one that arrived some other way — a hotfix, an older
 * migration, a table somebody made by hand.
 *
 * The judgment itself lives in {@see SnakeCaseIdentifiers} and is shared with the sister rule on
 * the other engine. What differs between the two is the SENTENCE, because what the engine does with
 * a mixed-case name differs, and advice that named the wrong mechanism would send its reader to the
 * wrong setting.
 */
final class SnakeCaseIdentifiersRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes, JudgesMigrationStatements
{
    /**
     * @param  NamingConvention  $naming  the shape a project asked for, built once by the registry
     *                                    and handed down — a rule that read the configuration would
     *                                    have a verdict its own tests cannot see
     */
    private readonly NamingConvention $naming;

    public function __construct(string $projectRoot = '', ?NamingConvention $naming = null)
    {
        parent::__construct($projectRoot);

        // Null is the shipped convention rather than "no convention": a rule with no pattern would
        // judge nothing and report nothing, which reads exactly like a database whose names are all
        // fine. The registry always passes one; this default is for a rule built directly in a test.
        $this->naming = $naming ?? NamingConvention::shipped();
    }

    /** @return non-empty-list<SchemaObjectType> */
    public function judgedObjectTypes(): array
    {
        return SnakeCaseIdentifiers::JUDGED_TYPES;
    }

    public function id(): string
    {
        return 'MY.L8.NAMING_SNAKE_CASE';
    }

    public function level(): Level
    {
        return Level::Conventions;
    }

    public function category(): Category
    {
        return Category::Convention;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Lint, Suite::Audit];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if (! in_array($object->type, SnakeCaseIdentifiers::JUDGED_TYPES, true)) {
            return [];
        }

        // One verdict for the object, naming every offender on it — the table's own name first and
        // then its members. Speaking once per object is this repository's convention for a catalog
        // rule and is held by an architecture test; a finding per member would also report the same
        // column twice on a reading that carries the table and its columns both.
        $offenders = [];

        $own = SnakeCaseIdentifiers::bareName($object->qualifiedName);

        if (! $this->naming->exempts($own) && SnakeCaseIdentifiers::violates($own, $this->naming->pattern)) {
            $offenders[] = $this->sentence($object->type->value, $own);
        }

        foreach (SnakeCaseIdentifiers::offendingMembers($object, $this->naming->pattern) as $name => $kind) {
            if ($this->naming->exempts($name)) {
                continue;
            }

            $offenders[] = $this->sentence($kind, $name);
        }

        return $offenders === []
            ? []
            : [RuleVerdict::flag(implode(' ', $offenders), $object->qualifiedName, $object->type)];
    }

    public function judgeStatement(MigrationStatementView $statement): ?RuleVerdict
    {
        // One verdict per statement, not one per name: the contract says a second verdict for the
        // same statement is deduplicated away by rule id and location, so a statement that creates
        // three badly-named columns would report one of them and drop two WITHOUT SAYING SO. The
        // names are gathered and reported together instead.
        $offending = [];

        foreach ($statement->targets as $target) {
            if (! in_array($target->type, SnakeCaseIdentifiers::JUDGED_TARGET_TYPES, true)) {
                continue;
            }

            $name = SnakeCaseIdentifiers::bareName($target->qualifiedName());

            if (! $this->naming->exempts($name) && SnakeCaseIdentifiers::violates($name, $this->naming->pattern)) {
                $offending[$name] = $target->type->value;
            }
        }

        if ($offending === []) {
            return null;
        }

        ksort($offending);

        $named = [];

        foreach ($offending as $name => $type) {
            $named[] = $this->sentence($type, $name);
        }

        return RuleVerdict::flag(implode(' ', $named));
    }

    private function sentence(string $type, string $name): string
    {
        return 'The '.$type.' `'.$name.'` is not snake_case: '.SnakeCaseIdentifiers::reason($name)
            .'. On MySQL what happens to it depends on lower_case_table_names, which differs between a developer machine and a Linux server.';
    }
}
