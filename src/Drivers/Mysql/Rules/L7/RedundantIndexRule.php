<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L7;

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
 * The judgment is shared with the PostgreSQL sister through {@see RedundantIndex}; what is MySQL's
 * own is the remedy, and the difference is worth stating. `DROP INDEX` on InnoDB is an in-place
 * operation that does not copy the table, so there is no CONCURRENTLY to ask for — but an index
 * that CARRIES A FOREIGN KEY cannot be dropped at all while the constraint stands, and MySQL
 * refuses the statement rather than silently leaving the key unindexed.
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
 * class, no method other than b-tree — which on this engine also excludes FULLTEXT and SPATIAL.
 * Each exclusion is a named catalog skip rather than a silent omission, so a schema full of them is
 * told they were not compared instead of being handed a clean report. {@see RedundantIndex} carries
 * the rest.
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
        return 'MY.L7.INDEX_REDUNDANT';
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
            .'to walk, for no read it serves alone. DROP INDEX is in place on InnoDB and copies no table — but '
            .'check first whether the index carries a foreign key, because MySQL refuses to drop one that does '
            .'rather than leave the constraint unindexed. Only indexes this reading could compare are considered '
            .'at all: a functional index, a prefix-length key, a non-b-tree method such as FULLTEXT or SPATIAL '
            .'are each excluded with a named reason, so a schema full of them is told they were not compared '
            .'rather than handed a clean report.',
            $object->qualifiedName,
            count($redundant) === 1 ? 'an index' : count($redundant).' indexes',
            implode('; ', $named),
        ))];
    }
}
