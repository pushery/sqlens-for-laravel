<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L5;

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
 * ## Why this is audit-only, and it is structural rather than a gap somebody left
 *
 * The lint half would need a migration statement to say what TYPE each column it creates holds, and
 * a `CREATE TABLE` carries none: {@see MigrationStatementDigest} exposes a
 * kind, its targets and an index's key columns, and nothing else. Reading the definitions back out
 * of the canonical text with a pattern is the one shortcut available, and it is the shortcut this
 * package refuses everywhere else — a reader that half-parses a column list reports a pair nobody
 * wrote, or misses one somebody did, and neither is visible from the finding.
 *
 * So the answer is the catalog's, where both columns and every index exist at once and the question
 * is a fact rather than an inference. The classifier gap is filed rather than worked around.
 *
 * ## Why PostgreSQL and MySQL both get one, unlike the foreign-key sister
 *
 * `PG.L5.FK_NO_INDEX` has no MySQL twin because InnoDB creates the missing index itself. Nothing
 * does that here: a polymorphic pair is not a declared relationship, so no engine knows it is one,
 * and both of them will read the whole table for as long as nobody writes the index. The rule is
 * the same judgment on both, which is why it is one helper and two thin classes.
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
        return 'PG.L5.MORPHS_NO_INDEX';
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

        if ($assessment['missing'] === [] && $assessment['reversed'] === []) {
            return [];
        }

        return [RuleVerdict::flag(PolymorphicPair::sentence(
            $object->getString('logical_name') ?? $object->qualifiedName,
            $assessment,
        ), $object->qualifiedName, $object->type)];
    }
}
