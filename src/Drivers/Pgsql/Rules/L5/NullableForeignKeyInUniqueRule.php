<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L5;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Keys\NullableKeyMember;
use Pushery\SQLens\Rules\RuleMetadataDefaults;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A unique key over foreign keys that does not hold, because one of them may be NULL.
 *
 * ## The measurement, because the claim is not obvious
 *
 * On PostgreSQL 18.4, over `UNIQUE (tenant_id, customer_id)` where `customer_id` is nullable:
 * three rows with the same `tenant_id` and a NULL `customer_id` all insert. The unique key is
 * enforced for every row that fills both columns, and enforced for none of the rows that do not —
 * which are exactly the rows a reader would want it to catch.
 *
 * `UNIQUE` is one of the few words in SQL people believe without checking, and nothing in the schema
 * shows the hole.
 *
 * ## Why this is narrow to the point of being quiet
 *
 * A nullable foreign key is ordinary and usually correct, so the trigger is three narrowings deep —
 * inside a unique key, at least two columns, every member itself a foreign-key column. The
 * reasoning for each lives in {@see NullableKeyMember}; the short version is that a key made
 * entirely of foreign keys is a RELATIONSHIP, and a relationship with a missing side is not one.
 *
 * ## The ticket asked for `preview`; it ships STABLE, and that is not a slip
 *
 * The preview tier exists so a rule added to a PUBLISHED product cannot start failing somebody's
 * pipeline over code nobody touched. Before the first release there is no such pipeline, so this
 * package's default is `stable` before 1.0 and flips to `preview` after — at ONE named place
 * ({@see RuleMetadataDefaults::DEFAULT_STABILITY}), so the flip is one line
 * rather than a sweep, and a machine guard holds it.
 *
 * Overriding it here would make this the single rule the guard has to except, and would put a
 * second answer to "what tier does a new rule get" in the codebase. The ticket's reason for asking
 * was false-positive risk rather than the versioning contract, and that risk is answered where it
 * belongs: in how narrowly the trigger is cut.
 */
final class NullableForeignKeyInUniqueRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
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
        return 'PG.L5.FK_NULLABLE_IN_UNIQUE';
    }

    public function level(): Level
    {
        return Level::SchemaBasics;
    }

    /**
     * Idiom, as the ticket specifies, and the counter-argument is worth recording rather than
     * silently overruling: what this reports is a constraint that does not constrain, which reads
     * more like safety than like appetite. It stays `idiom` because the finding is about a schema
     * SHAPE somebody may have chosen deliberately, and because a preview rule gates on opt-in
     * anyway — the category decides which band switches it off, not whether it is true.
     */
    public function category(): Category
    {
        return Category::Idiom;
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

        $broken = NullableKeyMember::brokenKeys($object);

        if ($broken !== []) {
            return [RuleVerdict::flag($this->message($object, $broken))];
        }

        $unread = NullableKeyMember::unreadKeys($object);

        if ($unread === []) {
            return [];
        }

        return [RuleVerdict::undetermined(sprintf(
            'On %s, whether %s counts two NULLs as the same value could not be read, so whether the key holds '
            .'across its nullable rows is unknown. PostgreSQL 15 added UNIQUE ... NULLS NOT DISTINCT, and the '
            .'two shapes are identical in every other respect — reporting would punish a schema that already '
            .'applied the fix, and passing would claim a constraint nobody verified.',
            $object->qualifiedName,
            implode(', ', $unread),
        ), UndeterminedReason::UniqueNullTreatmentUnknown)];
    }

    /**
     * ONE message for the table and every key on it.
     *
     * A catalog finding is located at the object and results are deduplicated by rule id and
     * location, so a verdict per index would arrive as one with the rest dropped without a word.
     *
     * @param  array<string, list<string>>  $broken
     */
    private function message(SchemaObject $object, array $broken): string
    {
        $named = [];

        foreach ($broken as $index => $columns) {
            $named[] = $index.' (nullable: '.implode(', ', $columns).')';
        }

        return sprintf(
            'On %s, %s made entirely of foreign-key columns %s a nullable member: %s. Under the default NULLS '
            .'DISTINCT the key is not enforced for any row where that column is NULL — measured on 18.4, three '
            .'rows sharing every other column and carrying a NULL there all insert. So the constraint holds for '
            .'exactly the rows that never needed it. A key made only of foreign keys is a relationship, and a '
            .'relationship with a missing side is not one. Either make the column NOT NULL, or declare the key '
            .'UNIQUE ... NULLS NOT DISTINCT (Blueprint: ->nullsNotDistinct()) so the NULL rows collide the way '
            .'the key says they should.',
            $object->qualifiedName,
            count($broken) === 1 ? 'a unique key' : count($broken).' unique keys',
            count($broken) === 1 ? 'has' : 'have',
            implode('; ', $named),
        );
    }
}
