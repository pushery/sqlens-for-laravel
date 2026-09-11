<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L6;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Keys\NarrowIntegerPrimaryKey;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * An integer primary key too narrow to grow into.
 *
 * ## The timing is the whole problem
 *
 * A signed `INT` key runs out at 2,147,483,647, and `MEDIUMINT` and `SMALLINT` far sooner. Nothing warns on the way there; the first
 * symptom is an INSERT failing on a table that has been working for years. And the moment the fix
 * becomes necessary is precisely the moment it is most expensive: widening the key rewrites the
 * table and every index over it, under a lock, on the largest table you have.
 *
 * Chosen early it costs four bytes a row. That asymmetry is the entire argument, and it is why this
 * is level 6 — an appetite for being told now rather than a defect to fail a build on.
 *
 * ## Deliberately blind to how big the table actually is
 *
 * No row estimate, no escalation by size. Statistics belong to the deploy suite, where a number
 * that changes between two runs is expected — an audit that read `reltuples` would report
 * differently on Tuesday than on Monday over an unchanged schema, and determinism is not a
 * property to trade for a sharper heading.
 *
 * ## What the finding cannot list
 *
 * Widening the key alone is half a fix: every referencing foreign-key column has to widen with it,
 * or the constraint stops matching. Those columns live on OTHER tables, and a rule judges one
 * object at a time — so the message says they must be widened without naming them. Claiming to
 * enumerate them from here would be a promise this rule cannot keep.
 */
final class NarrowIntegerPrimaryKeyRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
{
    /**
     * @param  string  $migrationsTable  the application's `database.migrations.table`, handed down
     *                                   rather than read here, like every other setting a rule
     *                                   judges by. The shipped default is Laravel's own name, so
     *                                   a driver built without it still exempts the ledger.
     */
    public function __construct(string $projectRoot, private readonly string $migrationsTable = 'migrations')
    {
        parent::__construct($projectRoot);
    }

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
        return 'MY.L6.PK_NOT_BIGINT';
    }

    public function level(): Level
    {
        return Level::TypeIdiom;
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

        // The framework's own migrations table is exempt, and it is the only table this rule
        // treats that way: Laravel creates it with `increments('id')` on every `migrate:install`,
        // so every Laravel application carries a narrow key there and none of them can act on the
        // advice. A finding nobody can resolve is noise in every report forever.
        if (NarrowIntegerPrimaryKey::isFrameworkMigrationsTable($object, $this->migrationsTable)) {
            return [];
        }

        $narrow = NarrowIntegerPrimaryKey::of($object);

        if ($narrow === null) {
            return [];
        }

        return [RuleVerdict::flag(sprintf(
            '%s has %s %s primary key on %s. A signed INT runs out at 2,147,483,647, a MEDIUMINT at 8,388,607 and a SMALLINT at '
            .'32,767 — with no warning on the way there: the first symptom is an INSERT failing on a table '
            .'that has worked for years. The fix is due exactly when it costs most, because widening the key '
            .'rewrites the table and every index over it, under a lock, on your largest table. Chosen now it '
            .'costs four bytes a row: $table->id() gives a BIGINT UNSIGNED. Widen the referencing foreign-key columns '
            .'in the same change — they live on other tables, so this finding cannot list them, and a key '
            .'widened without them stops matching.',
            $object->qualifiedName,
            NarrowIntegerPrimaryKey::article($narrow['type']),
            $narrow['type'],
            $narrow['column'],
        ))];
    }
}
