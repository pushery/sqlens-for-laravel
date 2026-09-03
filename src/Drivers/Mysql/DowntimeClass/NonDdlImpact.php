<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\DowntimeClass;

use Pushery\SQLens\Findings\DowntimeClass;

/**
 * What a NON-DDL statement does to a table, as the one named input the second downtime derivation
 * takes.
 *
 * The online-DDL matrix describes schema changes. A `WHERE`-less `UPDATE`, an unbatched backfill,
 * a `TRUNCATE` are not schema changes and will never have an entry — so without this, every
 * lifecycle finding would carry a permanent `undetermined`, and the first implementer to find that
 * unbearable would hard-code a class inside a rule. That is the outcome this enum exists to
 * prevent: the derivation stays in one place, with its reasoning written down and tested.
 *
 * It is an enum rather than a boolean or a string because the SET of cases is the decision. A new
 * kind of non-DDL impact has to be added here, next to the others, where the question "and what is
 * its lock reach?" is unavoidable — rather than answered inline at a call site nobody reviews.
 */
enum NonDdlImpact: string
{
    /**
     * A write with no predicate, or one whose predicate cannot bound it: the lock reach is the
     * whole table.
     *
     * `blocking` rather than `rewrite`: the rows are edited in place, not restructured. And
     * `blocking` rather than `online` regardless of how large the table turns out to be — the
     * class describes the REACH of the statement, not a guess at its duration, and a static reader
     * has no row count to guess with anyway.
     */
    case WholeTableWrite = 'whole_table_write';

    /**
     * `TRUNCATE`: the table's storage is replaced rather than its rows edited.
     *
     * `rewrite` is the honest class even though it is fast — the axis models what happens to the
     * table, and callers that treat `rewrite` as "needs a window" are right to for a statement
     * that discards every row.
     */
    case StorageReplacement = 'storage_replacement';

    /**
     * `DROP TABLE`: the table's storage is REMOVED rather than replaced or rewritten.
     *
     * Not a schema change, so the online-DDL matrix will never carry it — the matrix describes what
     * an `ALTER` does to a table that still exists afterwards. That is what puts it here rather than
     * leaving the class to be hard-coded inside a rule.
     *
     * `online` rather than `rewrite`, and the distinction from {@see self::StorageReplacement} is
     * the reason: `TRUNCATE` hands the table back empty, so a caller treating `rewrite` as "needs a
     * window" is right to pause. A drop unlinks and the table is gone — there is no scan, no
     * rebuild, and nothing left to be slow with. The danger is the irreversible LOSS, which the
     * level prices; this axis prices deploy TIME, and the two stay separate.
     *
     * It also matches what the PostgreSQL sibling states for the same statement. Reporting one
     * `DROP TABLE` as `online` and another as `rewrite` because of the engine would be a difference
     * a reader cannot act on.
     *
     * ⚠️ The counter-argument, stated rather than omitted: with InnoDB `file-per-table`, dropping a
     * very large table can stall the server while the filesystem unlinks its `.ibd`. MySQL 8.0+
     * releases the tablespace in the background, which is why this is a caveat and not the class.
     */
    case TableRemoval = 'table_removal';

    /**
     * A data write in the same statement stream as a schema change, where no single DDL operation
     * can be keyed.
     *
     * The lock belongs to the schema change, so when the operation IS known the caller looks the
     * class up in the matrix instead. This case is the honest floor for when it is not: the
     * combined statement holds a lock over the data write, and `blocking` is the least it can be.
     */
    case MixedWithSchemaChange = 'mixed_with_schema_change';

    /** The class this impact derives — the whole point of the enum, kept beside the reasoning. */
    public function downtimeClass(): DowntimeClass
    {
        return match ($this) {
            self::WholeTableWrite, self::MixedWithSchemaChange => DowntimeClass::Blocking,
            self::StorageReplacement => DowntimeClass::Rewrite,
            self::TableRemoval => DowntimeClass::Online,
        };
    }
}
