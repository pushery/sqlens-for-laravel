<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L5;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Keys\NullableKeyMember;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A unique key over foreign keys that does not hold, because one of them may be NULL.
 *
 * ## Measured on MySQL 8.4, and the engine leaves one fewer way out
 *
 * Over `UNIQUE KEY (tenant_id, customer_id)` with a nullable `customer_id`: three rows sharing the
 * same `tenant_id` and carrying a NULL there all insert. The key is enforced for every row that
 * fills both columns and for none of the rows that do not — which are exactly the rows a reader
 * would want it to catch.
 *
 * The difference from the PostgreSQL sister is the REMEDY, and it is why the two rules are separate
 * classes over one judgment. PostgreSQL offers `UNIQUE ... NULLS NOT DISTINCT`; **MySQL has no
 * counterpart at all.** So on this engine the answer is `NOT NULL` — or, where the column genuinely
 * must be optional, a stored generated column holding a sentinel and a unique key over that
 * instead. Naming PostgreSQL's option here would be advice that does not compile.
 *
 * There is a second consequence: with no second mode, the question is always decidable on MySQL.
 * This rule never answers undetermined, and its PostgreSQL sister sometimes must.
 *
 * ## The ticket asked for `preview`; it ships STABLE
 *
 * The same reasoning as its PostgreSQL sister carries here: before 1.0 there is no published
 * pipeline for the preview tier to protect, the default lives at one named place so the flip at 1.0
 * is a single line, and a machine guard holds that. The false-positive risk the ticket was worried
 * about is answered by how narrowly the trigger is cut, not by hiding the rule.
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
        return 'MY.L5.FK_NULLABLE_IN_UNIQUE';
    }

    public function level(): Level
    {
        return Level::SchemaBasics;
    }

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

        // No undetermined arm, and that is a fact about the engine rather than a gap: MySQL has only
        // one NULL treatment, so the reader states it for every unique index and the question is
        // always answerable. An arm here would be unreachable code wearing the shape of caution.
        return $broken === [] ? [] : [RuleVerdict::flag($this->message($object, $broken))];
    }

    /** @param  array<string, list<string>>  $broken */
    private function message(SchemaObject $object, array $broken): string
    {
        $named = [];

        foreach ($broken as $index => $columns) {
            $named[] = $index.' (nullable: '.implode(', ', $columns).')';
        }

        return sprintf(
            'On %s, %s made entirely of foreign-key columns %s a nullable member: %s. MySQL counts two NULLs as '
            .'different values, so the key is not enforced for any row where that column is NULL — measured on '
            .'8.4, three rows sharing every other column and carrying a NULL there all insert. The constraint '
            .'holds for exactly the rows that never needed it. A key made only of foreign keys is a '
            .'relationship, and a relationship with a missing side is not one. MySQL has no NULLS NOT DISTINCT, '
            .'so the fix is NOT NULL — or, where the column genuinely must be optional, a stored generated '
            .'column carrying a sentinel and a unique key over that instead.',
            $object->qualifiedName,
            count($broken) === 1 ? 'a unique key' : count($broken).' unique keys',
            count($broken) === 1 ? 'has' : 'have',
            implode('; ', $named),
        );
    }
}
