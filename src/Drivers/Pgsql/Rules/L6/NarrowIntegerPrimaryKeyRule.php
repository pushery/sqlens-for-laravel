<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L6;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Drivers\Pgsql\Rules\L5\PrimaryKeyNearCeilingRule;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Coverage\ForeignKeyIndexCoverage;
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
 * A signed `integer` key runs out at 2,147,483,647. Nothing warns on the way there; the first
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
 * How far the key's counter has got is a different question with a rule of its own:
 * {@see PrimaryKeyNearCeilingRule} reads it beside the catalog and reports the same key one level
 * earlier once it has used the configured share of its ceiling. This rule stays on the type.
 *
 * ## A bigint key on an integer sequence
 *
 * The column's type is not the whole width of a key. A `serial` column widened with `ALTER COLUMN
 * ... TYPE bigint` keeps a sequence `AS integer`, measured on PostgreSQL 18, and the insert after
 * 2,147,483,647 fails with "reached maximum value of sequence" although the column would hold the
 * value. The catalog reading records the sequence behind the key and its maximum, so such a key is
 * reported as well, with the cure that costs nothing: `ALTER SEQUENCE ... AS bigint` raises a maximum
 * that was the default of the narrower type without rewriting the table, measured. A narrow key fed
 * by a serial sequence is told the same thing, because widening its column alone would leave it
 * there. An identity column widens its sequence with it, so it is told nothing.
 *
 * ## What the finding cannot list
 *
 * Widening the key alone is half a fix: every referencing foreign-key column has to widen with it,
 * or the constraint stops matching. Those columns live on other tables, and a rule judges one
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
        return 'PG.L6.PK_NOT_BIGINT';
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
        // treats that way. Laravel creates it with `increments('id')` from
        // DatabaseMigrationRepository on every `migrate:install`, so every Laravel application on
        // PostgreSQL carries an integer key there — and none of them can act on the advice: the
        // table belongs to the framework, not to the application, and rewriting it would mean
        // writing against the framework's own default on a table the application does not own.
        // A finding nobody can resolve is noise in every report forever.
        //
        // Matched on the UNQUALIFIED name, because that is the shape the setting has: Laravel's
        // `database.migrations.table` names a table, never a schema. A second table of that name
        // in another schema is exempt too, and that is the honest trade for not inventing a
        // schema the setting does not carry.
        if (NarrowIntegerPrimaryKey::isFrameworkMigrationsTable($object, $this->migrationsTable)) {
            return [];
        }

        $narrow = NarrowIntegerPrimaryKey::of($object);

        if ($narrow === null) {
            return $this->narrowSequence($object);
        }

        return [RuleVerdict::flag(sprintf(
            '%s has %s %s primary key on %s. A signed integer runs out at 2,147,483,647 and a smallint at '
            .'32,767 — with no warning on the way there: the first symptom is an INSERT failing on a table '
            .'that has worked for years. The fix is due exactly when it costs most, because widening the key '
            .'rewrites the table and every index over it, under a lock, on your largest table. Chosen now it '
            .'costs four bytes a row: $table->id() gives a bigint. Widen the referencing foreign-key columns '
            .'in the same change — they live on other tables, so this finding cannot list them, and a key '
            .'widened without them stops matching.%s',
            $object->qualifiedName,
            NarrowIntegerPrimaryKey::article($narrow['type']),
            $narrow['type'],
            $narrow['column'],
            $this->sequenceFollows($object, $narrow['column']),
        ))];
    }

    /**
     * A bigint key whose sequence stops at the integer ceiling or below, or nothing.
     *
     * A maximum above the integer ceiling and below the bigint one is a cap somebody set on purpose
     * and is left alone. One at or below it makes a bigint key run out like an integer one, which is
     * what a widened serial column leaves behind.
     *
     * @return list<RuleVerdict>
     */
    private function narrowSequence(SchemaObject $table): array
    {
        $key = NarrowIntegerPrimaryKey::integerKey($table);
        $sequence = $table->getString('primary_key_sequence');
        $max = $table->getInt('primary_key_sequence_max');
        $integerCeiling = NarrowIntegerPrimaryKey::CEILING['integer']['signed'];

        if ($key === null || $key['type'] !== 'bigint' || $sequence === null || $max === null || $max > $integerCeiling) {
            return [];
        }

        return [RuleVerdict::flag(sprintf(
            '%s has a bigint primary key on %s, and the sequence behind it, %s, stops at %s: the key runs out '
            .'there like an integer one. A serial column widened with ALTER COLUMN ... TYPE bigint keeps its '
            .'sequence AS integer, and the first INSERT past that number fails with "reached maximum value of '
            .'sequence". ALTER SEQUENCE %s AS bigint raises a maximum that was the default of the narrower type '
            .'without rewriting the table; a maximum set by hand needs NO MAXVALUE in the same statement.',
            $table->qualifiedName,
            $key['column'],
            $sequence,
            number_format($max, 0, '.', ','),
            $sequence,
        ))];
    }

    /**
     * The sentence a narrow key fed by a serial sequence needs, or nothing.
     *
     * Widening the column alone leaves a serial sequence `AS integer`. An identity column widens its
     * sequence with it, and a key no sequence fills has none to widen, so both get nothing.
     */
    private function sequenceFollows(SchemaObject $table, string $column): string
    {
        $sequence = $table->getString('primary_key_sequence');
        $identity = ForeignKeyIndexCoverage::parse($table->getString('identity_columns') ?? '');

        if ($sequence === null || array_key_exists($column, $identity)) {
            return '';
        }

        return sprintf(
            ' Widen its sequence in the same change: ALTER COLUMN ... TYPE bigint leaves the serial sequence '
            .'%s AS integer, and ALTER SEQUENCE %s AS bigint lifts it without rewriting the table.',
            $sequence,
            $sequence,
        );
    }
}
