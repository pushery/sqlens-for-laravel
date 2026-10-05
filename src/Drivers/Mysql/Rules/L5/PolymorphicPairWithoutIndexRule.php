<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L5;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Keys\PolymorphicPair;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\MigrationStatementDigest;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A polymorphic column pair with no index leading on its type column.
 *
 * Every access through a polymorphic relation reads both columns — the id is unique only within one
 * type — so without an index over the pair each one scans the table. {@see PolymorphicPair} argues
 * the shape, why the type column has to lead, and where the detection's limit is.
 *
 * ## Why this reads the catalog
 *
 * The question is whether ANY index on the table leads with the type column, and only the catalog
 * holds both columns and every index at once: a migration shows what it writes, not the indexes
 * the table already has or the one a later migration adds. There the answer is a fact rather than
 * an inference. A statement's own column types are not the obstacle — the classifier carries them
 * in {@see MigrationStatementDigest::$columnDefinitions} — but a pair judged from one migration
 * would still be judged without the indexes around it.
 *
 * ## Why this engine gets one although it has no foreign-key twin
 *
 * MySQL is deliberately absent from the foreign-key-without-index rule, because InnoDB creates that
 * index itself — measured, it forecloses every case the rule could report. **It does nothing of the
 * kind here.** A polymorphic pair is not a declared relationship; it is two ordinary columns whose
 * meaning lives in the application, so no engine knows they belong together and none of them writes
 * the index. The absence that is right over there is wrong here, which is why this rule is one
 * shared judgment and two thin classes.
 */
final class PolymorphicPairWithoutIndexRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
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
        return 'MY.L5.MORPHS_NO_INDEX';
    }

    public function level(): Level
    {
        return Level::SchemaBasics;
    }

    /**
     * Performance, not safety: nothing is lost or corrupted, every read through the relation is
     * simply a scan — and classifying it as safety would put it in the band a project gates its
     * deploys on.
     */
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

        $assessment = PolymorphicPair::assess($object);

        if ($assessment['missing'] === [] && $assessment['reversed'] === [] && $assessment['invisible'] === []) {
            return [];
        }

        return [RuleVerdict::flag(PolymorphicPair::sentence(
            $object->getString('logical_name') ?? $object->qualifiedName,
            $assessment,
        ), $object->qualifiedName, $object->type)];
    }
}
