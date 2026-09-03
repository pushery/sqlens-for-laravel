<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L5;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Keys\TableKeyState;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A live table with no primary key and nothing that can stand in for one.
 *
 * On PostgreSQL the cost is not felt until the day it matters, which is what makes it worth a
 * rule rather than a habit:
 *
 * - **Logical replication refuses the row.** A table with the default `REPLICA IDENTITY` and no
 *   primary key cannot be replicated for `UPDATE` or `DELETE` at all — the server raises *cannot
 *   update table … because it does not have a replica identity*. The publication is created
 *   happily; the error arrives on the first write, in production, on the table nobody expected.
 * - **Row-level tooling has nothing to hold on to.** Auditing, change-data-capture and any
 *   "re-run just this row" recovery need an identity, and a table without one leaves manual
 *   `ctid` surgery, which is not stable across a `VACUUM FULL`.
 * - **Deduplication becomes guesswork.** Two rows a human would call identical are two different
 *   rows the database is happy to keep forever.
 *
 * ## What counts as keyed, and why a UNIQUE index can be enough
 *
 * A `UNIQUE` index over columns that are all `NOT NULL` is a real substitute: it is exactly what
 * `REPLICA IDENTITY USING INDEX` accepts. The index has to be a plain, complete one — partial,
 * expression and invalid indexes cannot serve, and the reading already tells those apart. The
 * decision lives in {@see TableKeyState}, shared with the migration reading of the same question,
 * so a project cannot be told a table is fine by one suite and broken by the other.
 *
 * ## What it does not report
 *
 * A partition is judged at its parent, never per partition: the key is a property of the
 * partitioned table, and reporting n partitions would multiply one finding by however many the
 * table happens to have. Extension-owned tables are somebody else's design — PostGIS alone
 * installs several — and views have no rows of their own to identify.
 *
 * A deliberately keyless log or staging table is a real case. It is handled the way every
 * intentional exception in this package is: with a config ignore carrying its reason, never by
 * weakening the rule until it stops seeing the real ones. There is deliberately no built-in list
 * of table names to skip — see the rule's page for why Laravel's own tables need none.
 */
final class TableWithoutPrimaryKeyRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
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
        return 'PG.L5.NO_PRIMARY_KEY';
    }

    /**
     * Level 5, where the generic table puts it — and deliberately not level 2, where MySQL's twin
     * sits.
     *
     * That is not an inconsistency. On MySQL the same condition breaks every online schema-change
     * tool and can be rejected outright by `sql_require_primary_key`, which is deploy-blocking
     * risk. On PostgreSQL the consequences are real but arrive later and elsewhere: replication
     * and row-level tooling, not the migration in front of you. Rule membership is per driver by
     * design, so each engine's level is the one its own consequences argue for.
     */
    public function level(): Level
    {
        return Level::SchemaBasics;
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
        if ($object->type !== SchemaObjectType::Table) {
            return [];
        }

        // A partition's key is its parent's; an extension's tables are its own design. Both are
        // read and present in the snapshot — they are simply not this rule's business, which is a
        // different thing from not being there.
        if ($object->isPartition || $object->fromExtension) {
            return [];
        }

        $name = $object->getString('logical_name') ?? $object->qualifiedName;

        return match (TableKeyState::inCatalog($object)) {
            TableKeyState::Keyed => [],
            TableKeyState::Unkeyed => [RuleVerdict::flag($this->unkeyedMessage($name))],
            TableKeyState::Undetermined => [RuleVerdict::undetermined(
                $this->undeterminedMessage($name),
                UndeterminedReason::TableKeyUndetermined,
            )],
        };
    }

    private function unkeyedMessage(string $table): string
    {
        return sprintf(
            '%s has no primary key and no UNIQUE index over NOT NULL columns that could stand in for one. '
            .'Logical replication cannot carry an UPDATE or a DELETE on such a table — the server answers '
            .'"cannot update table … because it does not have a replica identity", and it answers it on the '
            .'first write rather than when the publication is created. Row-level auditing and any '
            .'re-run-just-this-row recovery have nothing to identify a row by either. Add a key: $table->id() '
            .'in a migration, or ALTER TABLE %s ADD PRIMARY KEY (…) when a natural one already exists and is '
            .'NOT NULL.',
            $table,
            $table,
        );
    }

    private function undeterminedMessage(string $table): string
    {
        return sprintf(
            '%s has no primary key, and whether one of its UNIQUE indexes can stand in for one could not be '
            .'settled: the nullability of at least one indexed column was not read. A UNIQUE index qualifies '
            .'as a REPLICA IDENTITY only when every one of its columns is NOT NULL, so this is the fact the '
            .'answer turns on. Check the column definitions, or re-run the audit with access to the full '
            .'column catalog.',
            $table,
        );
    }
}
