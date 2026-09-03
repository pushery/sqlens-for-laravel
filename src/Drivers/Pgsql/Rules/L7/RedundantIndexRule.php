<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L7;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Indexes\RedundantIndex;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * An index another index already covers.
 *
 * The judgment is shared with the MySQL sister through {@see RedundantIndex}; what is PostgreSQL's
 * own is the remedy — `DROP INDEX CONCURRENTLY`, which this engine has and MySQL does not need.
 *
 * ## What this rule will not do
 *
 * It does not drop anything, and it never will: SQLens writes nothing to a database. The finding
 * carries the statement so a human can run it in a window they chose.
 *
 * ## The exclusions are the rule
 *
 * A naive left-prefix test is wrong on the first real schema it meets — and wrong in the expensive
 * direction, because its advice is to DROP something. Only indexes the reading already judged
 * comparable are compared at all: no partial index, no expression index, no non-default operator
 * class, no method other than b-tree, nothing PostgreSQL marked invalid. Each exclusion is a named
 * catalog skip rather than a silent omission, so a schema full of partial indexes is told they were
 * not compared instead of being handed a clean report. {@see RedundantIndex} carries the rest.
 */
final class RedundantIndexRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
{
    /**
     * Tables only — a run that read none produced no subject for this rule, and the report has to be
     * able to say so rather than let the silence read as a clean answer.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Table];
    }

    public function id(): string
    {
        return 'PG.L7.INDEX_REDUNDANT';
    }

    public function level(): Level
    {
        return Level::PerformanceHeuristics;
    }

    public function category(): Category
    {
        return Category::Performance;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Table) {
            return [];
        }

        $redundant = RedundantIndex::on($object);

        if ($redundant === []) {
            return [];
        }

        $named = [];

        foreach ($redundant as $index => $cover) {
            $named[] = $index.' (covered by '.$cover.')';
        }

        return [RuleVerdict::flag(sprintf(
            'On %s, %s whose work another index already does: %s. A b-tree index on (a) beside one on (a, b) '
            .'answers nothing the second cannot, and is still maintained on every insert and on every update '
            .'that touches its columns — it occupies its own pages in cache and is one more relation for vacuum '
            .'to walk, for no read it serves alone. Drop it outside peak with DROP INDEX CONCURRENTLY, which '
            .'takes no lock that blocks reads or writes. Only indexes this reading could compare are considered '
            .'at all: a partial index, an expression index, a non-default operator class, a method other than '
            .'b-tree and an invalid index are each excluded with a named reason, so a schema full of them is '
            .'told they were not compared rather than handed a clean report.',
            $object->qualifiedName,
            count($redundant) === 1 ? 'an index' : count($redundant).' indexes',
            implode('; ', $named),
        ))];
    }
}
